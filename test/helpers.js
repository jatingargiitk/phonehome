// Build DNS messages and TLS ClientHellos for tests.
export function dnsQuery(name, type = 1, id = 0x1234) {
  const parts = [Buffer.from([id >> 8, id & 255, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])];
  for (const label of name.split('.')) parts.push(Buffer.from([label.length]), Buffer.from(label));
  parts.push(Buffer.from([0, type >> 8, type & 255, 0, 1]));
  return Buffer.concat(parts);
}

// Response with a CNAME (pointing at the question name) and an A record.
export function dnsResponseCname(name, cname, ip, id = 0x1234) {
  const q = dnsQuery(name, 1, id);
  q[2] = 0x81;
  q[3] = 0x80;
  q[7] = 2; // ancount
  const cn = [];
  for (const label of cname.split('.')) cn.push(Buffer.from([label.length]), Buffer.from(label));
  cn.push(Buffer.from([0]));
  const cnData = Buffer.concat(cn);
  const rr1 = Buffer.concat([Buffer.from([0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, cnData.length]), cnData]);
  const cnOffset = q.length + 12; // where the cname name starts
  const rr2 = Buffer.from([0xc0 | (cnOffset >> 8), cnOffset & 255, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...ip.split('.').map(Number)]);
  return Buffer.concat([q, rr1, rr2]);
}

export const hex = (buf) => [...buf].map((b) => '\\x' + b.toString(16).padStart(2, '0')).join('');
