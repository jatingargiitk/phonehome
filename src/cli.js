import fs from 'node:fs';
import { createRequire } from 'node:module';
import { traceCommand } from './run.js';
import { loadTrace, analyze } from './analyze.js';
import { verdict } from './verdict.js';
import { parseAllow } from './allow.js';
import { renderText, renderMarkdown, toJson } from './report.js';
import { scanModelDir, renderScan, failsAt } from './scan.js';
import { checkEnv, renderEnv } from './env.js';

const require = createRequire(import.meta.url);
const VERSION = require('../package.json').version;

const HELP = `phonehome ${VERSION}: prove your local model stack makes zero network calls

Usage:
  phonehome [options] -- <command> [args...]   trace a command and its children
  phonehome --pid <pid> [options]              attach to a running process (needs ptrace rights)
  phonehome analyze <trace-dir|file> [options] report on an existing strace -ff -yy -x output
  phonehome scan <model-dir|file>... [--json] [--fail-on high|medium|low|info|none]
  phonehome env                                show telemetry / offline switches in this shell

Trace options:
  --allow <rule>        allowed host (example.com, *.example.com), IP or CIDR, optional :port.
                        Repeat or comma-separate. Loopback is always local.
  --timeout <dur>       stop the command after a duration (e.g. 30, 30s, 2m) and report
  --json                print the report as JSON on stdout (command stdout goes to stderr)
  --md <file>           also write a Markdown report with a result badge
  --keep-trace <dir>    keep the raw strace files (they contain traffic payload snippets)
  --opt-out-env         set documented telemetry/offline env switches for the command
  --egress-exit-code N  exit code when unexpected egress is seen (default 1)
  --no-color            plain output

Exit codes: unexpected egress -> 1 (or --egress-exit-code); otherwise the
command's own exit code (0 if stopped by --timeout); phonehome errors -> 2.
Linux only for tracing (uses strace). scan and env work everywhere.`;

function parseDuration(s) {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)?$/.exec(String(s));
  if (!m) throw new Error(`bad duration: ${s}`);
  const n = Number(m[1]);
  return Math.round(n * { ms: 1, s: 1000, m: 60000, h: 3600000 }[m[2] || 's']);
}

export function parseArgs(argv) {
  const opts = { mode: 'run', allow: [], json: false, md: null, timeoutMs: null, pid: null, keepTrace: null, optOutEnv: false, egressExit: 1, color: process.stderr.isTTY && !process.env.NO_COLOR, failOn: 'high', paths: [], command: [] };
  const dash = argv.indexOf('--');
  const own = dash === -1 ? argv : argv.slice(0, dash);
  if (dash !== -1) opts.command = argv.slice(dash + 1);
  const need = (i, flag) => {
    if (i + 1 >= own.length) throw new Error(`${flag} needs a value`);
    return own[i + 1];
  };
  let sawPositional = false;
  for (let i = 0; i < own.length; i++) {
    const a = own[i];
    if (!a.startsWith('-') && !sawPositional) {
      sawPositional = true;
      if (['scan', 'env', 'analyze', 'run'].includes(a)) {
        opts.mode = a;
        continue;
      }
      if (dash === -1) {
        // `phonehome node app.js`: everything from here is the command.
        opts.command = own.slice(i);
        break;
      }
    }
    if (a === '-h' || a === '--help') opts.mode = 'help';
    else if (a === '-v' || a === '--version') opts.mode = 'version';
    else if (a === '--allow') opts.allow.push(...need(i++, a).split(',').filter(Boolean));
    else if (a.startsWith('--allow=')) opts.allow.push(...a.slice(8).split(',').filter(Boolean));
    else if (a === '--json') opts.json = true;
    else if (a === '--md') opts.md = need(i++, a);
    else if (a === '--timeout') opts.timeoutMs = parseDuration(need(i++, a));
    else if (a === '--pid' || a === '-p') opts.pid = Number(need(i++, a));
    else if (a === '--keep-trace') opts.keepTrace = need(i++, a);
    else if (a === '--opt-out-env') opts.optOutEnv = true;
    else if (a === '--egress-exit-code') opts.egressExit = Number(need(i++, a));
    else if (a === '--no-color') opts.color = false;
    else if (a === '--fail-on') opts.failOn = need(i++, a);
    else if (a.startsWith('-')) throw new Error(`unknown option ${a} (see phonehome --help)`);
    else opts.paths.push(a);
  }
  if (opts.mode === 'run' && !opts.command.length && !opts.pid) {
    if (opts.paths.length) throw new Error(`put the command after --, e.g. phonehome -- ${opts.paths.join(' ')}`);
    opts.mode = 'help';
  }
  if (!['high', 'medium', 'low', 'info', 'none'].includes(opts.failOn)) throw new Error(`bad --fail-on ${opts.failOn}`);
  return opts;
}

function report(v, opts, extra) {
  if (opts.md) fs.writeFileSync(opts.md, renderMarkdown(v, { command: extra.command }));
  if (opts.json) process.stdout.write(JSON.stringify(toJson(v, { version: VERSION, ...extra }), null, 2) + '\n');
  else process.stderr.write('\n' + renderText(v, { command: extra.command, color: opts.color }) + '\n');
  if (opts.md && !opts.json) process.stderr.write(`phonehome: wrote ${opts.md}\n`);
}

export async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.mode === 'help') {
    process.stdout.write(HELP + '\n');
    return 0;
  }
  if (opts.mode === 'version') {
    process.stdout.write(VERSION + '\n');
    return 0;
  }
  if (opts.mode === 'env') {
    process.stdout.write(renderEnv(checkEnv()) + '\n');
    return 0;
  }
  if (opts.mode === 'scan') {
    if (!opts.paths.length) throw new Error('scan needs a model directory or file');
    const results = opts.paths.map((p) => scanModelDir(p, { env: process.env }));
    if (opts.json) process.stdout.write(JSON.stringify(results.length === 1 ? results[0] : results, null, 2) + '\n');
    else process.stdout.write(results.map(renderScan).join('\n\n') + '\n');
    return results.some((r) => failsAt(r, opts.failOn)) ? 1 : 0;
  }

  const rules = opts.allow.map(parseAllow);

  if (opts.mode === 'analyze') {
    if (!opts.paths.length) throw new Error('analyze needs a trace directory or file');
    const v = verdict(analyze(loadTrace(opts.paths[0])), rules);
    v.platform = 'linux';
    report(v, opts, {});
    return v.summary.unexpected ? opts.egressExit : 0;
  }

  if (process.platform !== 'linux') {
    throw new Error(`tracing needs Linux + strace (this is ${process.platform}). "phonehome scan" and "phonehome env" work here; for tracing, run inside a Linux VM or container.`);
  }
  const run = await traceCommand({
    command: opts.command,
    pid: opts.pid,
    timeoutMs: opts.timeoutMs,
    optOutEnv: opts.optOutEnv,
    stdout: opts.json ? process.stderr : 'inherit',
  });
  try {
    const files = fs.readdirSync(run.traceDir);
    if (!files.length) throw new Error('strace produced no trace. Is ptrace allowed here? (Docker: --cap-add SYS_PTRACE; attaching to another user\'s process needs sudo.)');
    const v = verdict(analyze(loadTrace(run.traceDir)), rules);
    v.platform = 'linux';
    v.stopped = run.stopped;
    const command = opts.pid ? [`pid ${opts.pid}`] : opts.command;
    report(v, opts, { command, durationMs: run.durationMs, exitCode: run.exitCode });
    if (opts.keepTrace) {
      fs.mkdirSync(opts.keepTrace, { recursive: true });
      for (const f of files) fs.copyFileSync(`${run.traceDir}/${f}`, `${opts.keepTrace}/${f}`);
    }
    if (v.summary.unexpected) return opts.egressExit;
    if (run.stopped) return 0;
    return run.exitCode ?? 1;
  } finally {
    fs.rmSync(run.traceDir, { recursive: true, force: true });
  }
}
