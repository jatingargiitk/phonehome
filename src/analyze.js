// Turn parsed strace records into a network picture: processes, DNS
// lookups, and outbound destinations (host/IP, port, process, count).

import fs from 'node:fs';
import path from 'node:path';
import { parseLine, buffers, parseExec, cloneIsThread } from './strace.js';
import { parseDns, parseTlsSni, parseHttpHost, parseVarlink } from './protocols.js';
import { normalizeIp, isLocal, classifyIp } from './net.js';

const SEND = new Set(['sendto', 'sendmsg', 'sendmmsg', 'write', 'writev']);
const RECV = new Set(['recvfrom', 'recvmsg', 'recvmmsg', 'read', 'readv']);
const CLONE = new Set(['clone', 'clone3', 'fork', 'vfork']);

/** Read `prefix.<tid>` files written by `strace -ff -o prefix` (or one combined file). */
export function loadTrace(target) {
  const records = [];
  const stat = fs.statSync(target);
  const files = [];
  if (stat.isDirectory()) {
    for (const f of fs.readdirSync(target)) {
      const m = /\.(\d+)$/.exec(f);
      if (m) files.push({ file: path.join(target, f), tid: Number(m[1]) });
    }
  } else {
    files.push({ file: target, tid: null });
  }
  for (const { file, tid } of files) {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    let seq = 0;
    for (const line of lines) {
      const rec = parseLine(line);
      if (!rec) continue;
      rec.tid = rec.pid ?? tid ?? 0;
      rec.seq = seq++;
      records.push(rec);
    }
  }
  return records;
}

function sortRecords(records) {
  return [...records].sort((a, b) => {
    if (a.ts != null && b.ts != null && a.ts !== b.ts) return a.ts - b.ts;
    if (a.tid !== b.tid) return 0;
    return a.seq - b.seq;
  });
}

const isDnsPort = (p) => p === 53;
const isResolvedSocket = (p) => typeof p === 'string' && p.includes('io.systemd.Resolve');

/**
 * Analyze records into { processes, lookups, connections, probes, resolvers, local }.
 * `rootPid` (optional) is the traced command's pid.
 */
export function analyze(records, { rootPid = null } = {}) {
  const recs = sortRecords(records);
  const tgidOf = new Map(); // tid -> tgid
  const parentOf = new Map(); // tgid -> parent tgid
  const exeOf = new Map(); // tgid -> { path, argv }
  const fdPeer = new Map(); // `${tgid}:${fd}` -> { ip, port, proto } | { unix }
  const ipNames = new Map(); // ip -> Set(names)
  const cnameOf = new Map(); // alias -> original name
  const lookups = new Map();
  const dests = new Map();
  const udpPending = new Map(); // `${tgid}:${fd}` -> dest key (connected UDP sockets not yet used)
  const resolvers = new Map();
  const local = new Map();

  const tg = (tid) => {
    let t = tid;
    for (let i = 0; i < 64 && tgidOf.has(t); i++) t = tgidOf.get(t);
    return t;
  };

  // First pass: thread/process tree and executables (order-independent).
  for (const r of recs) {
    if (CLONE.has(r.name) && r.ret != null && r.ret > 0) {
      if (cloneIsThread(r)) tgidOf.set(r.ret, r.tid);
      else parentOf.set(r.ret, tg(r.tid));
    }
  }
  for (const r of recs) {
    if ((r.name === 'execve' || r.name === 'execveat') && r.ret === 0) {
      const e = parseExec(r.args);
      if (e) exeOf.set(tg(r.tid), e);
    }
  }
  const procName = (tgid) => {
    for (let p = tgid, i = 0; p != null && i < 64; p = parentOf.get(p), i++) {
      const e = exeOf.get(p);
      if (e) return path.basename(e.path);
    }
    return `pid ${tgid}`;
  };
  const procLabel = (tgid) => `${procName(tgid)}[${tgid}]`;

  const addLookup = (name, type, tgid, server) => {
    const l = lookups.get(name) || { name, types: new Set(), processes: new Set(), count: 0, answers: new Set(), servers: new Set() };
    l.types.add(type);
    l.processes.add(procLabel(tgid));
    l.count++;
    if (server) l.servers.add(server);
    lookups.set(name, l);
  };
  const addAnswer = (msg) => {
    for (const a of msg.answers) {
      const original = cnameOf.get(a.name) || a.name;
      if (a.type === 'CNAME') cnameOf.set(a.data, original);
      else if (a.type === 'A' || a.type === 'AAAA') {
        const ip = normalizeIp(a.data);
        if (!ipNames.has(ip)) ipNames.set(ip, new Set());
        ipNames.get(ip).add(original);
        const l = lookups.get(original);
        if (l) l.answers.add(ip);
      }
    }
  };
  const addResolver = (ip, port) => {
    const key = `${ip}:${port}`;
    resolvers.set(key, (resolvers.get(key) || 0) + 1);
    return key;
  };
  const destKey = (proto, ip, port) => `${proto} ${ip} ${port}`;
  const addDest = (proto, ip, port, tgid, outcome, how) => {
    ip = normalizeIp(ip);
    if (isLocal(ip)) {
      const k = `${proto} ${ip}:${port}`;
      local.set(k, (local.get(k) || 0) + 1);
      return null;
    }
    const key = destKey(proto, ip, port);
    const d = dests.get(key) || {
      proto, ip, port, kind: classifyIp(ip), hosts: new Set(), processes: new Set(), count: 0, outcomes: new Set(), via: new Set(),
    };
    d.count++;
    d.processes.add(procLabel(tgid));
    if (outcome) d.outcomes.add(outcome);
    if (how) d.via.add(how);
    dests.set(key, d);
    return key;
  };
  const outcomeOf = (r) => (r.ret != null && r.ret >= 0 ? 'ok' : r.errno || 'error');
  const protoOf = (r) => {
    const k = r.fd?.kind || '';
    if (k.startsWith('TCP')) return 'tcp';
    if (k.startsWith('UDP')) return 'udp';
    return 'ip';
  };

  for (const r of recs) {
    const tgid = tg(r.tid);
    const fdKey = r.fd ? `${tgid}:${r.fd.num}` : null;

    if (r.name === 'connect') {
      const inet = r.addrs.find((a) => a.family === 4 || a.family === 6);
      const unix = r.addrs.find((a) => a.family === 'unix');
      if (unix && fdKey) fdPeer.set(fdKey, { unix: unix.path });
      if (!inet || !fdKey) continue;
      const proto = protoOf(r);
      const ip = normalizeIp(inet.ip);
      fdPeer.set(fdKey, { ip, port: inet.port, proto });
      if (isDnsPort(inet.port)) {
        addResolver(ip, inet.port);
        continue;
      }
      if (proto === 'udp') {
        // A UDP connect sends no packet by itself (glibc uses it to pick a
        // source address). Only count it once data is written.
        udpPending.set(fdKey, { proto, ip, port: inet.port, tgid, outcome: outcomeOf(r) });
        continue;
      }
      addDest(proto, ip, inet.port, tgid, outcomeOf(r), 'connect');
      continue;
    }

    if (SEND.has(r.name) || RECV.has(r.name)) {
      if (r.ret != null && r.ret < 0 && RECV.has(r.name)) continue;
      const peer = fdKey ? fdPeer.get(fdKey) : null;
      const explicit = r.addrs.find((a) => a.family === 4 || a.family === 6);
      const target = explicit ? { ip: normalizeIp(explicit.ip), port: explicit.port, proto: protoOf(r) } : peer;
      if (!target) continue;

      if (target.unix !== undefined) {
        if (!isResolvedSocket(target.unix)) continue;
        for (const b of buffers(r)) {
          const v = parseVarlink(b);
          if (!v) continue;
          for (const n of v.names) addLookup(n, 'A/AAAA', tgid, 'systemd-resolved');
          for (const ip of v.addresses) {
            const name = v.replyName || [...lookups.keys()].pop();
            if (!name) continue;
            const n = normalizeIp(ip);
            if (!ipNames.has(n)) ipNames.set(n, new Set());
            ipNames.get(n).add(name);
            lookups.get(name)?.answers.add(n);
          }
        }
        continue;
      }

      if (isDnsPort(target.port)) {
        if (SEND.has(r.name) && explicit) addResolver(target.ip, target.port);
        for (const b of buffers(r)) {
          const msg = parseDns(b, { tcp: target.proto === 'tcp' });
          if (!msg) continue;
          if (!msg.response && SEND.has(r.name)) {
            for (const q of msg.questions) addLookup(q.name, q.type, tgid, `${target.ip}:${target.port}`);
          } else if (msg.response) {
            addAnswer(msg);
          }
        }
        continue;
      }

      if (!SEND.has(r.name)) continue;
      let key;
      if (explicit) {
        key = addDest(target.proto, target.ip, target.port, tgid, outcomeOf(r), r.name);
      } else if (udpPending.has(fdKey)) {
        const p = udpPending.get(fdKey);
        udpPending.delete(fdKey);
        key = addDest(p.proto, p.ip, p.port, p.tgid, p.outcome, 'connect+send');
      } else {
        key = destKey(target.proto, target.ip, target.port);
      }
      const d = key && dests.get(key);
      if (d && target.proto !== 'udp') {
        for (const b of buffers(r)) {
          const host = parseTlsSni(b) || parseHttpHost(b);
          if (host) d.hosts.add(host);
        }
      }
    }
  }

  // UDP sockets that were connected but never carried data.
  const probes = [];
  for (const p of udpPending.values()) {
    if (isLocal(p.ip)) continue;
    probes.push({ proto: p.proto, ip: p.ip, port: p.port, process: procLabel(p.tgid) });
  }

  for (const d of dests.values()) {
    for (const n of ipNames.get(d.ip) || []) d.hosts.add(n);
  }

  const processes = [];
  const seen = new Set([...exeOf.keys(), ...parentOf.keys()]);
  if (rootPid) seen.add(rootPid);
  for (const tgid of [...seen].sort((a, b) => a - b)) {
    const e = exeOf.get(tgid);
    processes.push({ pid: tgid, parent: parentOf.get(tgid) ?? null, name: procName(tgid), argv: e ? e.argv : null });
  }

  // Resolver traffic we could not decode still means a lookup happened.
  if (resolvers.size && lookups.size === 0) {
    lookups.set('(undecoded DNS query)', {
      name: '(undecoded DNS query)', types: new Set(['?']), processes: new Set(), count: [...resolvers.values()].reduce((a, b) => a + b, 0),
      answers: new Set(), servers: new Set(resolvers.keys()),
    });
  }

  const arr = (s) => [...s].sort();
  return {
    processes,
    lookups: [...lookups.values()]
      .map((l) => ({ name: l.name, types: arr(l.types), processes: arr(l.processes), count: l.count, answers: arr(l.answers), servers: arr(l.servers) }))
      .sort((a, b) => a.name.localeCompare(b.name)),
    connections: [...dests.values()]
      .map((d) => ({ proto: d.proto, ip: d.ip, port: d.port, kind: d.kind, hosts: arr(d.hosts), processes: arr(d.processes), count: d.count, outcomes: arr(d.outcomes) }))
      .sort((a, b) => b.count - a.count || a.ip.localeCompare(b.ip) || a.port - b.port),
    probes,
    resolvers: [...resolvers.entries()].map(([addr, count]) => ({ addr, count })),
    local: [...local.entries()].map(([addr, count]) => ({ addr, count })),
  };
}
