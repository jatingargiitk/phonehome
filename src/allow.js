// --allow rules: hostnames (exact, *.suffix), IPs, CIDRs, each with an
// optional :port. Loopback is always local and never counts as egress.
import { parseCidr, inCidr, normalizeIp } from './net.js';
import { isIP } from 'node:net';

export function parseAllow(text) {
  let s = String(text).trim().toLowerCase();
  if (!s) throw new Error('empty --allow value');
  let port = null;
  // [v6]:port, v4:port, host:port. A bare IPv6 has several colons and no port.
  const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
  if (bracket) {
    s = bracket[1];
    port = bracket[2] ? Number(bracket[2]) : null;
  } else if ((s.match(/:/g) || []).length === 1) {
    const [h, p] = s.split(':');
    if (!/^\d+$/.test(p)) throw new Error(`bad port in --allow ${text}`);
    s = h;
    port = Number(p);
  }
  if (isIP(normalizeIp(s.split('/')[0])) || s.includes('/')) {
    const cidr = parseCidr(s);
    if (!cidr) throw new Error(`bad address in --allow ${text}`);
    return { raw: String(text), type: 'cidr', cidr, port };
  }
  if (!/^(\*\.)?[a-z0-9_\-]+(\.[a-z0-9_\-]+)*\.?$/.test(s)) throw new Error(`bad host in --allow ${text}`);
  const wildcard = s.startsWith('*.');
  return { raw: String(text), type: 'host', host: (wildcard ? s.slice(2) : s).replace(/\.$/, ''), wildcard, port };
}

function hostMatches(rule, name) {
  const n = name.toLowerCase().replace(/\.$/, '');
  if (rule.wildcard) return n.endsWith('.' + rule.host);
  return n === rule.host;
}

export function lookupAllowed(rules, name) {
  if (name === 'localhost' || name.endsWith('.localhost')) return true;
  return rules.some((r) => r.type === 'host' && hostMatches(r, name));
}

export function connectionAllowed(rules, conn) {
  return rules.some((r) => {
    if (r.port != null && r.port !== conn.port) return false;
    if (r.type === 'cidr') return inCidr(conn.ip, r.cidr);
    return conn.hosts.some((h) => hostMatches(r, h));
  });
}

export function resolverAllowed(rules, addr) {
  const ip = addr.replace(/:(\d+)$/, '');
  return rules.some((r) => r.type === 'cidr' && inCidr(ip, r.cidr));
}
