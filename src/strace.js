// Parse strace output (as written by `strace -ff -yy -x -o prefix`) into
// structured syscall records. One file per thread id; lines have no pid
// prefix. Lines with a leading pid (plain `-f -o file`) are accepted too.

import { stringLiterals } from './cstring.js';

// The return value may carry an -yy annotation too: `= 7<TCP:[a->b]>`.
const RESULT_RE = /\)\s+=\s+(-?\d+|\?|0x[0-9a-f]+)(<.*?>)?(?:\s+([A-Z][A-Z0-9_]*))?(?:\s+\(([^)]*)\))?\s*$/;
const HEAD_RE = /^(?:(\d+)\s+)?(?:\[pid\s+(\d+)\]\s+)?(?:(\d+(?::\d+){0,2}(?:\.\d+)?)\s+)?([a-z_0-9]+)\(/;

/**
 * Parse a single strace line. Returns null for lines that are not complete
 * syscalls (exit notices, signals, unfinished/resumed fragments).
 */
export function parseLine(line) {
  if (!line || line.startsWith('+++') || line.startsWith('---')) return null;
  const head = HEAD_RE.exec(line);
  if (!head) return null;
  if (line.includes('<unfinished ...>') || line.includes(' resumed>')) return null;
  const tail = RESULT_RE.exec(line);
  if (!tail) return null;
  const argsStart = head[0].length;
  const argsEnd = tail.index;
  const args = line.slice(argsStart, argsEnd);
  const ret = tail[1] === '?' ? null : Number(tail[1]);
  return {
    pid: head[1] ? Number(head[1]) : head[2] ? Number(head[2]) : null,
    ts: head[3] && /^\d+\.\d+$/.test(head[3]) ? Number(head[3]) : null,
    name: head[4],
    args,
    ret,
    errno: tail[3] || null,
    retFd: tail[2] && ret != null ? parseFd(`${ret}${tail[2]}`) : null,
    fd: parseFd(args),
    addrs: parseSockaddrs(args),
  };
}

// `21<UDP:[172.30.0.2:46668->198.18.0.53:53]>` -> { num: 21, kind: 'UDP', local, peer }
export function parseFd(args) {
  const m = /^(\d+)<((?:[^\[>]|\[(?:[^\[\]]|\[[^\]]*\])*\])*)>/.exec(args);
  if (!m) return null;
  const num = Number(m[1]);
  const desc = m[2];
  const sock = /^(TCP|TCPv6|UDP|UDPv6|UDPLITE|UDPLITEv6|UNIX|UNIX-STREAM|UNIX-DGRAM|UNIX-SEQPACKET|NETLINK|RAW|RAWv6|PING|PINGv6|socket):\[(.*)\]$/.exec(desc);
  if (!sock) return { num, kind: 'other', desc };
  const kind = sock[1];
  const inner = sock[2];
  const fd = { num, kind, desc };
  const pair = /^(.*)->(.*)$/.exec(inner);
  if (pair && /^(TCP|UDP|UDPLITE)/.test(kind)) {
    fd.local = splitHostPort(pair[1]);
    fd.peer = splitHostPort(pair[2]);
  } else if (/^(TCP|UDP)/.test(kind) && /:\d+$/.test(inner)) {
    fd.local = splitHostPort(inner);
  }
  return fd;
}

function splitHostPort(s) {
  const v6 = /^\[(.*)\]:(\d+)$/.exec(s);
  if (v6) return { ip: v6[1], port: Number(v6[2]) };
  const v4 = /^(.*):(\d+)$/.exec(s);
  if (v4) return { ip: v4[1], port: Number(v4[2]) };
  return null;
}

// All IPv4/IPv6/unix socket addresses mentioned in the arguments.
export function parseSockaddrs(args) {
  const out = [];
  const re = /\{sa_family=(AF_INET6?|AF_UNIX|AF_UNSPEC|AF_NETLINK)(.*?)\}/g;
  let m;
  while ((m = re.exec(args))) {
    const fam = m[1];
    const body = m[2];
    if (fam === 'AF_INET') {
      const a = /sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)/.exec(body);
      if (a) out.push({ family: 4, ip: a[2], port: Number(a[1]) });
    } else if (fam === 'AF_INET6') {
      const port = /sin6_port=htons\((\d+)\)/.exec(body);
      const ip = /inet_pton\(AF_INET6, "([^"]+)"/.exec(body);
      if (port && ip) out.push({ family: 6, ip: ip[1], port: Number(port[1]) });
    } else if (fam === 'AF_UNIX') {
      const p = /sun_path=@?"((?:[^"\\]|\\.)*)"/.exec(body);
      out.push({ family: 'unix', path: p ? p[1] : '' });
    } else if (fam === 'AF_UNSPEC') {
      out.push({ family: 'unspec' });
    }
  }
  return out;
}

// Decoded data buffers in the call (string literals that aren't paths/addresses).
export function buffers(rec) {
  const cleaned = rec.args
    .replace(/sun_path=@?"(?:[^"\\]|\\.)*"/g, '')
    .replace(/inet_(?:addr|pton)\((?:AF_INET6, )?"[^"]*"/g, '');
  return stringLiterals(cleaned);
}

// execve("/usr/bin/curl", ["curl", "-s", ...], ...) -> { path, argv }
export function parseExec(args) {
  const m = /^"((?:[^"\\]|\\.)*)", \[(.*?)\](?:\.\.\.)?, /.exec(args);
  if (!m) return null;
  const argv = [];
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let a;
  while ((a = re.exec(m[2]))) argv.push(a[1]);
  return { path: m[1], argv };
}

// Does this clone create a thread (shares the thread group) or a process?
export function cloneIsThread(rec) {
  return /CLONE_THREAD/.test(rec.args);
}
