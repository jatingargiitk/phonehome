// End-to-end tests: run the CLI under real strace. Skipped if strace is
// missing or ptrace is not permitted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const bin = path.join(here, '..', 'bin', 'phonehome.js');
const fake = path.join(here, 'fixtures', 'scripts', 'fake-egress.js');
const root = path.join(here, '..');

const probe = spawnSync('strace', ['-qq', '-e', 'trace=none', 'true']);
const canTrace = process.platform === 'linux' && probe.status === 0;
const skip = canTrace ? false : 'strace not available or ptrace not permitted';

const run = (args, opts = {}) => spawnSync(process.execPath, [bin, '--no-color', ...args], { encoding: 'utf8', timeout: 60000, ...opts });

test('help and version need no strace', () => {
  const h = run(['--help']);
  assert.equal(h.status, 0);
  assert.match(h.stdout, /phonehome scan/);
  assert.equal(run(['--version']).stdout.trim(), JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).version);
  const bad = run(['--bogus']);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /unknown option/);
});

test('a no-network command reports 0 egress and keeps its exit code', { skip }, () => {
  const r = run(['--', process.execPath, path.join(root, 'examples', 'no-network.js')]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /loopback GET -> ok/);
  assert.match(r.stderr, /0 egress/);
  assert.match(r.stderr, /loopback/);
  const failing = run(['--', 'sh', '-c', 'exit 3']);
  assert.equal(failing.status, 3);
  assert.match(failing.stderr, /0 egress/);
});

test('DNS query and TCP connect are detected and exit 1', { skip }, () => {
  const r = run(['--', process.execPath, fake]);
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /phonehome-test\.example/);
  assert.match(r.stderr, /192\.0\.2\.10:8443/);
  assert.match(r.stderr, /egress detected/);
});

test('--json gives machine-readable output on stdout', { skip }, () => {
  const r = run(['--json', '--', process.execPath, fake]);
  const j = JSON.parse(r.stdout);
  assert.equal(j.result, 'unexpected-egress');
  assert.deepEqual(j.lookups.map((l) => l.name), ['phonehome-test.example']);
  assert.deepEqual(j.resolvers.map((x) => x.addr), ['192.0.2.53:53']);
  assert.ok(j.connections.some((c) => c.ip === '192.0.2.10' && c.port === 8443 && c.proto === 'tcp'));
  assert.equal(j.exitCode, 0);
});

test('--allow covers expected egress; --egress-exit-code changes the code', { skip }, () => {
  const ok = run(['--allow', 'phonehome-test.example', '--allow', '192.0.2.0/24', '--', process.execPath, fake, '4']);
  assert.equal(ok.status, 4, ok.stderr);
  assert.match(ok.stderr, /0 unexpected egress/);
  const partial = run(['--allow', 'phonehome-test.example', '--egress-exit-code', '9', '--', process.execPath, fake]);
  assert.equal(partial.status, 9);
  assert.match(partial.stderr, /1 destination not on the allowlist/);
});

test('child processes are followed and named', { skip }, () => {
  const r = run(['--json', '--', 'sh', '-c', `"${process.execPath}" "${fake}"; true`]);
  const j = JSON.parse(r.stdout);
  assert.ok(j.processes.some((p) => p.name === 'sh'));
  const c = j.connections.find((x) => x.ip === '192.0.2.10');
  assert.match(c.processes[0], /^node\[\d+\]$/);
});

test('--timeout stops a long-running command; --md writes a badge; --keep-trace keeps files', { skip }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ph-cli-'));
  const md = path.join(dir, 'report.md');
  const keep = path.join(dir, 'trace');
  const t0 = Date.now();
  const r = run(['--timeout', '1s', '--md', md, '--keep-trace', keep, '--', 'sh', '-c', 'sleep 30']);
  assert.ok(Date.now() - t0 < 20000, 'should stop early');
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /stopped|timeout/i);
  assert.match(fs.readFileSync(md, 'utf8'), /img\.shields\.io\/badge\/phonehome-0%20egress-brightgreen/);
  assert.ok(fs.readdirSync(keep).length > 0);
  const again = run(['analyze', keep]);
  assert.equal(again.status, 0);
  assert.match(again.stderr, /0 egress/);
});

test('--opt-out-env sets telemetry switches for the command', { skip }, () => {
  const r = run(['--opt-out-env', '--', 'sh', '-c', 'echo "$HF_HUB_OFFLINE $DO_NOT_TRACK $VLLM_NO_USAGE_STATS"']);
  assert.equal(r.stdout.trim(), '1 1 1');
});

test('env subcommand lists switches', () => {
  const r = run(['env'], { env: { ...process.env, HF_HUB_OFFLINE: '1', DO_NOT_TRACK: '' } });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /✓ HF_HUB_OFFLINE/);
  assert.match(r.stdout, /export DO_NOT_TRACK=1/);
});
