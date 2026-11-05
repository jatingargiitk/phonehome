// Run a command (or attach to a pid) under strace and collect the trace.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const TRACED_SYSCALLS = [
  'execve', 'execveat', 'clone', 'clone3', 'fork', 'vfork',
  'connect', 'sendto', 'sendmsg', 'sendmmsg', 'recvfrom', 'recvmsg', 'recvmmsg',
  'read', 'write', 'writev',
];

// Documented opt-out switches for telemetry / online checks in common
// local-model tooling. --opt-out-env sets them for the traced command.
export const OPT_OUT_ENV = {
  HF_HUB_OFFLINE: '1',
  HF_HUB_DISABLE_TELEMETRY: '1',
  TRANSFORMERS_OFFLINE: '1',
  HF_DATASETS_OFFLINE: '1',
  DO_NOT_TRACK: '1',
  VLLM_NO_USAGE_STATS: '1',
  VLLM_DO_NOT_TRACK: '1',
  GRADIO_ANALYTICS_ENABLED: 'False',
  ANONYMIZED_TELEMETRY: 'False',
};

export function findStrace(env = process.env) {
  for (const dir of (env.PATH || '').split(path.delimiter)) {
    const p = path.join(dir, 'strace');
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {}
  }
  return null;
}

function straceFeatures(bin) {
  const r = spawnSync(bin, ['-h'], { encoding: 'utf8' });
  const help = `${r.stdout || ''}${r.stderr || ''}`;
  return { seccomp: help.includes('--seccomp-bpf'), killOnExit: help.includes('--kill-on-exit') };
}

export function straceArgs({ prefix, command, pid, features = {} }) {
  const args = ['-ff', '-qq', '-yy', '-x', '-ttt', '-s', '1024', '-e', 'signal=none', '-e', `trace=${TRACED_SYSCALLS.join(',')}`, '-o', prefix];
  if (pid) return [...args, '-p', String(pid)];
  if (features.seccomp) args.push('--seccomp-bpf');
  if (features.killOnExit) args.push('--kill-on-exit');
  return [...args, '--', ...command];
}

function descendants(pid) {
  const out = [];
  const walk = (p) => {
    let tasks = [];
    try {
      tasks = fs.readdirSync(`/proc/${p}/task`);
    } catch {
      return;
    }
    for (const t of tasks) {
      let kids = '';
      try {
        kids = fs.readFileSync(`/proc/${p}/task/${t}/children`, 'utf8');
      } catch {}
      for (const k of kids.split(/\s+/).filter(Boolean).map(Number)) {
        if (!out.includes(k)) {
          out.push(k);
          walk(k);
        }
      }
    }
  };
  walk(pid);
  return out;
}

function signalTree(rootPid, sig) {
  for (const p of descendants(rootPid)) {
    try {
      process.kill(p, sig);
    } catch {}
  }
}

/**
 * Trace `command` (array) or attach to `pid`. Resolves to
 * { traceDir, exitCode, signal, stopped, durationMs }.
 */
export function traceCommand({ command, pid, timeoutMs, env = process.env, optOutEnv = false, stdout = 'inherit', straceBin } = {}) {
  const bin = straceBin || findStrace(env);
  if (!bin) {
    const err = new Error('strace not found on PATH. Install it (Debian/Ubuntu: sudo apt-get install strace; Fedora: sudo dnf install strace).');
    err.code = 'NO_STRACE';
    throw err;
  }
  const traceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phonehome-'));
  fs.chmodSync(traceDir, 0o700);
  const prefix = path.join(traceDir, 'trace');
  const args = straceArgs({ prefix, command, pid, features: straceFeatures(bin) });
  const childEnv = optOutEnv ? { ...env, ...OPT_OUT_ENV } : env;
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { stdio: ['inherit', stdout, 'inherit'], env: childEnv });
    let stopped = null;
    const timers = [];
    const stop = (why) => {
      if (stopped) return;
      stopped = why;
      const target = pid ? null : child.pid;
      if (target) signalTree(target, 'SIGINT');
      else child.kill('SIGINT'); // detaching strace from an attached pid
      timers.push(setTimeout(() => (target ? signalTree(target, 'SIGTERM') : child.kill('SIGTERM')), 5000));
      timers.push(setTimeout(() => {
        if (target) signalTree(target, 'SIGKILL');
        child.kill('SIGKILL');
      }, 10000));
    };
    if (timeoutMs) timers.push(setTimeout(() => stop(`${Math.round(timeoutMs / 1000)}s timeout`), timeoutMs));
    // Ctrl-C in a terminal already reaches the whole foreground group;
    // when phonehome alone is signalled (scripts, CI), pass it on.
    const onSignal = (sig) => {
      if (process.stdin.isTTY && !pid) return;
      stop(`${sig}`);
    };
    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
    child.on('error', reject);
    child.on('exit', (code, signal) => {
      timers.forEach(clearTimeout);
      process.off('SIGINT', onSignal);
      process.off('SIGTERM', onSignal);
      resolve({ traceDir, exitCode: code, signal, stopped, durationMs: Date.now() - started });
    });
  });
}
