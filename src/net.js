// IP address helpers: parsing, CIDR matching and classification.
import { isIPv4, isIPv6 } from 'node:net';

export function ipToBigInt(ip) {
  if (isIPv4(ip)) {
    return { family: 4, value: ip.split('.').reduce((acc, o) => (acc << 8n) + BigInt(Number(o)), 0n) };
  }
  if (isIPv6(ip)) {
    let s = ip;
    const v4tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (v4tail) {
      const o = v4tail[1].split('.').map(Number);
      s = s.slice(0, -v4tail[1].length) + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
    }
    const [left, right] = s.split('::');
    const l = left ? left.split(':') : [];
    const r = right !== undefined ? (right ? right.split(':') : []) : [];
    const missing = 8 - l.length - r.length;
    const groups = right !== undefined ? [...l, ...Array(missing).fill('0'), ...r] : l;
    if (groups.length !== 8) return null;
    return { family: 6, value: groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g || '0', 16)), 0n) };
  }
  return null;
}

/** Unwrap ::ffff:a.b.c.d to a.b.c.d. */
export function normalizeIp(ip) {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return m ? m[1] : ip.toLowerCase();
}

export function parseCidr(text) {
  const [ip, bitsText] = text.split('/');
  const parsed = ipToBigInt(normalizeIp(ip));
  if (!parsed) return null;
  const max = parsed.family === 4 ? 32 : 128;
  const bits = bitsText === undefined ? max : Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > max) return null;
  return { family: parsed.family, value: parsed.value, bits, max };
}

export function inCidr(ip, cidr) {
  const p = ipToBigInt(normalizeIp(ip));
  if (!p || p.family !== cidr.family) return false;
  const shift = BigInt(cidr.max - cidr.bits);
  return p.value >> shift === cidr.value >> shift;
}

const RANGES = [
  ['loopback', '127.0.0.0/8'],
  ['loopback', '::1/128'],
  ['unspecified', '0.0.0.0/8'],
  ['unspecified', '::/128'],
  ['metadata', '169.254.169.254/32'],
  ['metadata', 'fd00:ec2::254/128'],
  ['link-local', '169.254.0.0/16'],
  ['link-local', 'fe80::/10'],
  ['private', '10.0.0.0/8'],
  ['private', '172.16.0.0/12'],
  ['private', '192.168.0.0/16'],
  ['private', '100.64.0.0/10'],
  ['private', 'fc00::/7'],
  ['documentation', '192.0.2.0/24'],
  ['documentation', '198.51.100.0/24'],
  ['documentation', '203.0.113.0/24'],
  ['documentation', '2001:db8::/32'],
  ['benchmarking', '198.18.0.0/15'],
  ['multicast', '224.0.0.0/4'],
  ['multicast', 'ff00::/8'],
].map(([kind, c]) => ({ kind, cidr: parseCidr(c) }));

/** loopback | unspecified | metadata | link-local | private | documentation | benchmarking | multicast | public */
export function classifyIp(ip) {
  const n = normalizeIp(ip);
  for (const r of RANGES) if (inCidr(n, r.cidr)) return r.kind;
  return 'public';
}

/** Traffic that never leaves the machine. */
export function isLocal(ip) {
  const k = classifyIp(ip);
  return k === 'loopback' || k === 'unspecified';
}
