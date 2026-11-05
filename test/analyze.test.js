import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadTrace, analyze } from '../src/analyze.js';
import { classifyIp, inCidr, parseCidr, normalizeIp } from '../src/net.js';
import { parseAllow, lookupAllowed, connectionAllowed } from '../src/allow.js';
import { verdict } from '../src/verdict.js';
import { badgeUrl, renderText, renderMarkdown, toJson, shellJoin } from '../src/report.js';
import { dnsQuery, hex } from './helpers.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, 'fixtures', 'node-https');

function traceFromLines(lines) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph-test-'));
  for (const [tid, body] of Object.entries(lines)) fs.writeFileSync(path.join(dir, `trace.${tid}`), body.join('\n') + '\n');
  return dir;
}

test('classifyIp', () => {
  assert.equal(classifyIp('127.0.0.53'), 'loopback');
  assert.equal(classifyIp('::1'), 'loopback');
  assert.equal(classifyIp('::ffff:127.0.0.1'), 'loopback');
  assert.equal(classifyIp('0.0.0.0'), 'unspecified');
  assert.equal(classifyIp('169.254.169.254'), 'metadata');
  assert.equal(classifyIp('10.1.2.3'), 'private');
  assert.equal(classifyIp('2001:db8::1'), 'documentation');
  assert.equal(classifyIp('198.18.0.1'), 'benchmarking');
  assert.equal(classifyIp('8.8.8.8'), 'public');
  assert.equal(normalizeIp('::ffff:192.0.2.1'), '192.0.2.1');
});

test('CIDR matching for v4 and v6', () => {
  assert.equal(inCidr('192.0.2.200', parseCidr('192.0.2.0/24')), true);
  assert.equal(inCidr('192.0.3.1', parseCidr('192.0.2.0/24')), false);
  assert.equal(inCidr('2001:db8::abcd', parseCidr('2001:db8::/32')), true);
  assert.equal(inCidr('192.0.2.1', parseCidr('2001:db8::/32')), false);
});

test('allow rules: hosts, wildcards, ports, CIDRs', () => {
  const rules = ['huggingface.co', '*.example.com:443', '192.0.2.0/24', '[2001:db8::1]:8080'].map(parseAllow);
  assert.equal(lookupAllowed(rules, 'huggingface.co'), true);
  assert.equal(lookupAllowed(rules, 'cdn.example.com'), true);
  assert.equal(lookupAllowed(rules, 'example.com'), false);
  assert.equal(lookupAllowed(rules, 'localhost'), true);
  assert.equal(connectionAllowed(rules, { ip: '203.0.113.5', port: 443, hosts: ['a.example.com'] }), true);
  assert.equal(connectionAllowed(rules, { ip: '203.0.113.5', port: 80, hosts: ['a.example.com'] }), false);
  assert.equal(connectionAllowed(rules, { ip: '192.0.2.9', port: 1, hosts: [] }), true);
  assert.equal(connectionAllowed(rules, { ip: '2001:db8::1', port: 8080, hosts: [] }), true);
  assert.equal(connectionAllowed(rules, { ip: '2001:db8::1', port: 80, hosts: [] }), false);
  assert.throws(() => parseAllow('bad host!'));
  assert.throws(() => parseAllow('example.com:http'));
});

test('real trace fixture: lookups and destinations attributed per process', () => {
  const a = analyze(loadTrace(fixture));
  assert.deepEqual(a.lookups.map((l) => l.name), ['example.com']);
  assert.deepEqual(a.lookups[0].processes.sort(), ['curl[92201]', 'node[92188]']);
  const dests = a.connections.map((c) => `${c.proto} ${c.ip}:${c.port} ${c.hosts.join(',')} ${c.processes.join(',')}`).sort();
  assert.deepEqual(dests, ['tcp 198.18.0.1:443 example.com node[92188]', 'tcp 198.18.0.1:80 example.com curl[92201]']);
  assert.ok(a.processes.some((p) => p.name === 'sh'));
});

test('UDP connect without data is a probe, loopback is local, DNS is decoded from sendto', () => {
  const q = hex(dnsQuery('updates.example.org'));
  const dir = traceFromLines({
    100: [
      '1.000001 execve("/usr/bin/tool", ["tool"], 0x1 /* 1 vars */) = 0',
      '1.000002 connect(3<UDP:[0.0.0.0:0]>, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("203.0.113.9")}, 16) = 0',
      '1.000003 connect(4<TCP:[127.0.0.1:5000]>, {sa_family=AF_INET, sin_port=htons(11434), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
      `1.000004 sendto(5<UDP:[0.0.0.0:40000]>, "${q}", 37, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.0.2.53")}, 16) = 37`,
    ],
  });
  const a = analyze(loadTrace(dir));
  assert.equal(a.connections.length, 0);
  assert.deepEqual(a.probes.map((p) => `${p.ip}:${p.port}`), ['203.0.113.9:9']);
  assert.equal(a.local.length, 1);
  assert.deepEqual(a.lookups.map((l) => [l.name, l.processes[0]]), [['updates.example.org', 'tool[100]']]);
  assert.deepEqual(a.resolvers.map((r) => r.addr), ['192.0.2.53:53']);
});

test('threads are attributed to their process, metadata IP flagged', () => {
  const dir = traceFromLines({
    200: [
      '1.0 execve("/usr/bin/server", ["server"], 0x1 /* 1 vars */) = 0',
      '1.1 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, exit_signal=0}, 88) = 201',
    ],
    201: ['1.2 connect(7<TCP:[10.0.0.2:40000]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("169.254.169.254")}, 16) = -1 EINPROGRESS (Operation now in progress)'],
  });
  const v = verdict(analyze(loadTrace(dir)));
  assert.equal(v.connections[0].processes[0], 'server[200]');
  assert.equal(v.connections[0].kind, 'metadata');
  assert.match(renderText(v), /metadata/i);
});

test('resolver contacted but query undecodable still counts as a lookup', () => {
  const dir = traceFromLines({
    300: ['1.0 sendto(3<UDP:[0.0.0.0:1]>, "\\x00\\x01", 2, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.0.2.53")}, 16) = 2'],
  });
  const v = verdict(analyze(loadTrace(dir)));
  assert.equal(v.summary.zeroEgress, false);
  assert.equal(v.lookups[0].name, '(undecoded DNS query)');
});

test('verdict, badge and reports', () => {
  const a = analyze(loadTrace(fixture));
  const bad = verdict(a);
  assert.equal(bad.summary.unexpected, 3);
  assert.match(badgeUrl(bad), /3%20unexpected%20egress-red$/);
  const ok = verdict(a, [parseAllow('example.com')]);
  assert.equal(ok.summary.unexpected, 0);
  assert.equal(ok.summary.allowed, 3);
  assert.match(badgeUrl(ok), /-green$/);
  const empty = verdict({ processes: [], lookups: [], connections: [], probes: [], resolvers: [], local: [] });
  assert.equal(empty.summary.zeroEgress, true);
  assert.match(badgeUrl(empty), /0%20egress-brightgreen$/);
  assert.match(renderText(empty), /0 egress/);
  assert.match(renderMarkdown(bad, { command: ['sh', '-c', 'x y'] }), /\| example\.com \|/);
  assert.equal(toJson(bad).result, 'unexpected-egress');
  assert.equal(toJson(ok).result, 'allowed-only');
  assert.equal(toJson(empty).result, 'zero-egress');
  assert.equal(shellJoin(['sh', '-c', "echo 'hi'"]), `sh -c 'echo '\\''hi'\\'''`);
});

test('a closed UDP probe fd reused by a TCP socket is not mixed up', () => {
  const dir = traceFromLines({
    400: [
      '1.0 connect(25<UDPv6:[[::]:0]>, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::7", &sin6_addr), sin6_scope_id=0}, 28) = 0',
      '1.1 close(25<UDPv6:[[2001:db8::2]:5000]>) = 0',
      '1.2 connect(25<TCP:[0.0.0.0:0]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.7")}, 16) = -1 EINPROGRESS (Operation now in progress)',
      '1.3 write(25<TCP:[192.0.2.2:40000->192.0.2.7:443]>, "hello", 5) = 5',
    ],
  });
  const a = analyze(loadTrace(dir));
  assert.deepEqual(a.connections.map((c) => [c.proto, c.ip, c.port, c.bytesSent]), [['tcp', '192.0.2.7', 443, 5]]);
  assert.deepEqual(a.probes.map((p) => `${p.ip}:${p.port}`), ['2001:db8::7:0']);
});

test('replies on accepted sockets are inbound, not egress', () => {
  const dir = traceFromLines({
    500: [
      '1.0 accept4(3<TCP:[0.0.0.0:11434]>, {sa_family=AF_INET, sin_port=htons(51000), sin_addr=inet_addr("192.0.2.50")}, [16], SOCK_CLOEXEC) = 7<TCP:[192.0.2.2:11434->192.0.2.50:51000]>',
      '1.1 write(7<TCP:[192.0.2.2:11434->192.0.2.50:51000]>, "HTTP/1.1 200 OK\\r\\n\\r\\n", 19) = 19',
    ],
  });
  const v = verdict(analyze(loadTrace(dir)));
  assert.equal(v.summary.zeroEgress, true);
  assert.deepEqual(v.inbound, [{ ip: '192.0.2.50', count: 1 }]);
  assert.match(renderText(v), /inbound/);
});
