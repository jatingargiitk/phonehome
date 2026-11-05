import test from 'node:test';
import assert from 'node:assert/strict';
import { unescapeC, stringLiterals } from '../src/cstring.js';
import { parseLine, parseFd, parseSockaddrs, parseExec, cloneIsThread } from '../src/strace.js';

test('unescapeC decodes hex, octal and simple escapes', () => {
  assert.deepEqual([...unescapeC('\\x00\\x41b\\n\\t\\\\\\"\\101')], [0, 0x41, 0x62, 10, 9, 92, 34, 65]);
});

test('stringLiterals pulls every quoted buffer, ignoring quotes inside escapes', () => {
  const lits = stringLiterals('3, "a\\"b", 5, "\\x01\\x02"');
  assert.equal(lits.length, 2);
  assert.equal(lits[0].toString(), 'a"b');
  assert.deepEqual([...lits[1]], [1, 2]);
});

test('parseLine reads a connect with a socket annotation and EINPROGRESS', () => {
  const r = parseLine('1762312345.123456 connect(21<TCP:[172.30.0.2:40000]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.215.14")}, 16) = -1 EINPROGRESS (Operation now in progress)');
  assert.equal(r.name, 'connect');
  assert.equal(r.ts, 1762312345.123456);
  assert.equal(r.ret, -1);
  assert.equal(r.errno, 'EINPROGRESS');
  assert.equal(r.fd.num, 21);
  assert.equal(r.fd.kind, 'TCP');
  assert.deepEqual(r.addrs, [{ family: 4, ip: '93.184.215.14', port: 443 }]);
});

test('parseLine accepts a pid prefix and [pid N] form', () => {
  assert.equal(parseLine('4242 getpid() = 4242').pid, 4242);
  assert.equal(parseLine('[pid  77] close(3) = 0').pid, 77);
});

test('parseLine skips exits, signals and split syscalls', () => {
  assert.equal(parseLine('+++ exited with 0 +++'), null);
  assert.equal(parseLine('--- SIGCHLD {si_signo=SIGCHLD} ---'), null);
  assert.equal(parseLine('1.5 read(3, <unfinished ...>'), null);
  assert.equal(parseLine('1.5 <... read resumed>"x", 1) = 1'), null);
});

test('parseFd reads UDP peer pairs, IPv6 and unix sockets', () => {
  const udp = parseFd('5<UDP:[172.30.0.2:46668->198.18.0.53:53]>, "x", 1');
  assert.deepEqual(udp.local, { ip: '172.30.0.2', port: 46668 });
  assert.deepEqual(udp.peer, { ip: '198.18.0.53', port: 53 });
  const v6 = parseFd('7<TCPv6:[[::1]:5000->[2001:db8::1]:443]>');
  assert.deepEqual(v6.peer, { ip: '2001:db8::1', port: 443 });
  assert.equal(parseFd('3</etc/hosts>').kind, 'other');
});

test('parseSockaddrs handles IPv6 and AF_UNIX', () => {
  const v6 = parseSockaddrs('{sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::53", &sin6_addr), sin6_scope_id=0}, 28');
  assert.deepEqual(v6, [{ family: 6, ip: '2001:db8::53', port: 53 }]);
  const un = parseSockaddrs('{sa_family=AF_UNIX, sun_path="/run/systemd/resolve/io.systemd.Resolve"}, 42');
  assert.equal(un[0].family, 'unix');
  assert.equal(un[0].path, '/run/systemd/resolve/io.systemd.Resolve');
});

test('parseExec and cloneIsThread', () => {
  const e = parseExec('"/usr/bin/curl", ["curl", "-s", "http://example.com"], 0x7ffd /* 20 vars */');
  assert.equal(e.path, '/usr/bin/curl');
  assert.deepEqual(e.argv, ['curl', '-s', 'http://example.com']);
  assert.equal(cloneIsThread(parseLine('1.0 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, exit_signal=0}, 88) = 101')), true);
  assert.equal(cloneIsThread(parseLine('1.0 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD) = 102')), false);
});
