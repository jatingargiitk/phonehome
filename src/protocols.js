// Small, defensive decoders for the protocol bytes strace shows us:
// DNS messages (queries and answers), the SNI name in a TLS ClientHello,
// the Host header of a plaintext HTTP request, and systemd-resolved's
// varlink JSON. Every decoder returns null on anything it doesn't
// recognise; strace truncates buffers, so partial data is normal.

const QTYPES = { 1: 'A', 5: 'CNAME', 28: 'AAAA', 65: 'HTTPS', 64: 'SVCB', 15: 'MX', 16: 'TXT', 12: 'PTR', 33: 'SRV', 2: 'NS', 6: 'SOA' };

function readName(buf, offset, depth = 0) {
  const labels = [];
  let pos = offset;
  let jumped = false;
  let end = offset;
  for (let guard = 0; guard < 128; guard++) {
    if (pos >= buf.length) return null;
    const len = buf[pos];
    if (len === 0) {
      if (!jumped) end = pos + 1;
      return { name: labels.join('.'), end };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length || depth > 16) return null;
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) end = pos + 2;
      jumped = true;
      if (ptr >= pos) return null;
      pos = ptr;
      depth++;
      continue;
    }
    if (len > 63 || pos + 1 + len > buf.length) return null;
    const label = buf.subarray(pos + 1, pos + 1 + len).toString('latin1');
    if (!/^[A-Za-z0-9_\-*]+$/.test(label)) return null;
    labels.push(label);
    pos += 1 + len;
  }
  return null;
}

/**
 * Decode a DNS message. `tcp` strips the 2-byte length prefix.
 * Returns { id, response, questions: [{name,type}], answers: [{name,type,data}] }.
 */
export function parseDns(buf, { tcp = false } = {}) {
  if (tcp) {
    if (buf.length < 14) return null;
    buf = buf.subarray(2);
  }
  if (buf.length < 17) return null;
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  const opcode = (flags >> 11) & 0xf;
  if (qd < 1 || qd > 4 || opcode !== 0) return null;
  const response = (flags & 0x8000) !== 0;
  let pos = 12;
  const questions = [];
  for (let i = 0; i < qd; i++) {
    const n = readName(buf, pos);
    if (!n || n.end + 4 > buf.length || !n.name) return null;
    const qtype = buf.readUInt16BE(n.end);
    const qclass = buf.readUInt16BE(n.end + 2);
    if (qclass !== 1 && qclass !== 255) return null;
    questions.push({ name: n.name.toLowerCase(), type: QTYPES[qtype] || String(qtype) });
    pos = n.end + 4;
  }
  const answers = [];
  for (let i = 0; i < an && response; i++) {
    const n = readName(buf, pos);
    if (!n || n.end + 10 > buf.length) break;
    const type = buf.readUInt16BE(n.end);
    const rdlen = buf.readUInt16BE(n.end + 8);
    const rd = n.end + 10;
    if (rd + rdlen > buf.length) break;
    let data = null;
    if (type === 1 && rdlen === 4) data = [...buf.subarray(rd, rd + 4)].join('.');
    else if (type === 28 && rdlen === 16) data = formatIPv6(buf.subarray(rd, rd + 16));
    else if (type === 5) {
      const c = readName(buf, rd);
      data = c ? c.name.toLowerCase() : null;
    }
    if (data) answers.push({ name: n.name.toLowerCase(), type: QTYPES[type] || String(type), data });
    pos = rd + rdlen;
  }
  return { id, response, questions, answers };
}

export function formatIPv6(bytes) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // collapse the longest run of zero groups
  let best = [-1, 0];
  for (let i = 0; i < 8; ) {
    if (groups[i] !== '0') { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > best[1]) best = [i, j - i];
    i = j;
  }
  if (best[1] < 2) return groups.join(':');
  const left = groups.slice(0, best[0]).join(':');
  const right = groups.slice(best[0] + best[1]).join(':');
  return `${left}::${right}`;
}

/** Server name from a TLS ClientHello (works on a truncated record if SNI is in range). */
export function parseTlsSni(buf) {
  if (buf.length < 48 || buf[0] !== 0x16 || buf[1] !== 0x03 || buf[5] !== 0x01) return null;
  let pos = 9; // record header (5) + handshake type (1) + length (3)
  pos += 2 + 32; // client version + random
  if (pos >= buf.length) return null;
  pos += 1 + buf[pos]; // session id
  if (pos + 2 > buf.length) return null;
  pos += 2 + buf.readUInt16BE(pos); // cipher suites
  if (pos >= buf.length) return null;
  pos += 1 + buf[pos]; // compression methods
  if (pos + 2 > buf.length) return null;
  pos += 2; // extensions length
  while (pos + 4 <= buf.length) {
    const type = buf.readUInt16BE(pos);
    const len = buf.readUInt16BE(pos + 2);
    const body = pos + 4;
    if (type === 0) {
      // server_name: list len (2), name type (1), name len (2), name
      if (body + 5 > buf.length) return null;
      const nameLen = buf.readUInt16BE(body + 3);
      if (body + 5 + nameLen > buf.length) return null;
      const name = buf.subarray(body + 5, body + 5 + nameLen).toString('latin1');
      return /^[A-Za-z0-9.\-_]+$/.test(name) ? name.toLowerCase() : null;
    }
    pos = body + len;
  }
  return null;
}

/** Host header of a plaintext HTTP/1.x request. */
export function parseHttpHost(buf) {
  const head = buf.subarray(0, 2048).toString('latin1');
  if (!/^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|CONNECT) \S+ HTTP\/1\.[01]\r?\n/.test(head)) return null;
  const m = /\r?\nhost:\s*([^\s\r\n:]+)/i.exec(head);
  return m ? m[1].toLowerCase() : null;
}

/** systemd-resolved varlink: ResolveHostname request name, and reply addresses. */
export function parseVarlink(buf) {
  const text = buf.toString('utf8');
  const out = { names: [], addresses: [] };
  if (/io\.systemd\.Resolve\.ResolveHostname/.test(text)) {
    const m = /"name"\s*:\s*"([^"]+)"/.exec(text);
    if (m) out.names.push(m[1].toLowerCase());
  }
  const addrRe = /"family"\s*:\s*(2|10)\s*,\s*"address"\s*:\s*\[([0-9,\s]+)\]/g;
  let a;
  while ((a = addrRe.exec(text))) {
    const bytes = a[2].split(',').map((x) => Number(x.trim()));
    if (a[1] === '2' && bytes.length === 4) out.addresses.push(bytes.join('.'));
    if (a[1] === '10' && bytes.length === 16) out.addresses.push(formatIPv6(bytes));
  }
  const nameReply = /"name"\s*:\s*"([^"]+)"/.exec(text);
  if (out.addresses.length && nameReply && !out.names.length) out.replyName = nameReply[1].toLowerCase();
  return out.names.length || out.addresses.length ? out : null;
}
