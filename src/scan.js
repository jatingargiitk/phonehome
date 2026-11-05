// Static scan of a model directory (Hugging Face snapshot, GGUF files,
// an Ollama model store) for things that can make a "local" model reach
// the network or run code: remote-code hooks, Python files, pickle
// weights, and URLs in chat templates and configs.
import fs from 'node:fs';
import path from 'node:path';
import { isGguf, readGgufMetadata } from './gguf.js';
import { checkEnv } from './env.js';

const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s"'<>`\\)\]}]+/gi;
const SEVERITY = ['high', 'medium', 'low', 'info'];
const MAX_TEXT = 50 * 1024 * 1024;
const SKIP_DIRS = new Set(['.git', 'node_modules', '__pycache__', '.cache']);
const SKIP_JSON_PATHS = [/^model\.vocab(\.|$)/, /^model\.merges(\.|$)/];
const PROVENANCE_KEY = /(^|\.)(url|repo_url|license\.link|license_link|doi|homepage|_name_or_path|source\.url|source\.repo_url)$/i;
const PICKLE_EXT = new Set(['.bin', '.pt', '.pth', '.ckpt', '.pkl', '.pickle']);

const PY_CAPS = [
  ['network', /^\s*(?:import|from)\s+(socket|requests|urllib|urllib3|http\.client|httpx|aiohttp|websocket|websockets|ftplib|smtplib)\b/m],
  ['network', /\b(?:urlopen|requests\.(?:get|post|put)|socket\.socket|httpx\.(?:get|post|Client))\s*\(/],
  ['subprocess', /\b(?:subprocess\.\w+|os\.system|os\.popen|pty\.spawn)\s*\(/],
  ['dynamic-code', /(?<![\w.])(?:eval|exec|__import__)\s*\(|\bimportlib\.import_module\s*\(/],
  ['encoded-payload', /\b(?:base64\.b64decode|codecs\.decode|marshal\.loads|zlib\.decompress)\s*\(/],
];

function walk(root) {
  const files = [];
  const stack = [root];
  while (stack.length) {
    const p = stack.pop();
    let st;
    try {
      st = fs.lstatSync(p);
    } catch {
      continue;
    }
    if (st.isSymbolicLink()) {
      try {
        st = fs.statSync(p); // HF cache snapshots are symlinks into blobs/
      } catch {
        continue;
      }
    }
    if (st.isDirectory()) {
      if (p !== root && SKIP_DIRS.has(path.basename(p))) continue;
      for (const f of fs.readdirSync(p).sort().reverse()) stack.push(path.join(p, f));
    } else if (st.isFile()) {
      files.push({ file: p, size: st.size });
    }
  }
  return files;
}

function urlsIn(text) {
  return [...new Set((text.match(URL_RE) || []).map((u) => u.replace(/[.,;:]+$/, '')))];
}

function* jsonStrings(value, pathParts = []) {
  const p = pathParts.join('.');
  if (SKIP_JSON_PATHS.some((re) => re.test(p))) return;
  if (typeof value === 'string') yield { path: p, value };
  else if (Array.isArray(value)) for (let i = 0; i < value.length; i++) yield* jsonStrings(value[i], [...pathParts, String(i)]);
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) yield* jsonStrings(v, [...pathParts, k]);
}

function findKey(value, key, pathParts = [], out = []) {
  if (Array.isArray(value)) value.forEach((v, i) => findKey(v, key, [...pathParts, String(i)], out));
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (k === key) out.push({ path: [...pathParts, k].join('.'), value: v });
      findKey(v, key, [...pathParts, k], out);
    }
  }
  return out;
}

const isTemplateKey = (p) => /template/i.test(p);

function urlFindings(rel, where, text, { template }) {
  return urlsIn(text).map((url) => {
    if (template) return { severity: 'medium', rule: 'url-in-template', file: rel, where, message: 'URL inside a chat template (rendered into every prompt)', evidence: url };
    if (PROVENANCE_KEY.test(where)) return { severity: 'info', rule: 'source-link', file: rel, where, message: 'provenance/licence link in metadata', evidence: url };
    return { severity: 'low', rule: 'url-in-config', file: rel, where, message: 'URL in model config/metadata', evidence: url };
  });
}

function scanJson(rel, file, findings, autoMapRefs) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return;
  }
  for (const hit of findKey(data, 'auto_map')) {
    const refs = [];
    for (const { value } of jsonStrings(hit.value)) refs.push(value);
    for (const ref of refs) {
      const remote = ref.includes('--');
      const module = (remote ? ref.split('--')[1] : ref).split('.')[0];
      autoMapRefs.add(module + '.py');
      findings.push({
        severity: 'high',
        rule: remote ? 'remote-code-other-repo' : 'remote-code-auto-map',
        file: rel,
        where: hit.path,
        message: remote
          ? `auto_map loads code from another repository (${ref.split('--')[0]}) when trust_remote_code=True`
          : `auto_map loads ${module}.py when trust_remote_code=True`,
        evidence: ref,
      });
    }
  }
  for (const hit of findKey(data, 'trust_remote_code')) {
    if (hit.value === true || hit.value === 'true') {
      findings.push({ severity: 'medium', rule: 'trust-remote-code-set', file: rel, where: hit.path, message: 'config sets trust_remote_code to true', evidence: 'true' });
    }
  }
  for (const s of jsonStrings(data)) findings.push(...urlFindings(rel, s.path, s.value, { template: isTemplateKey(s.path) }));
}

function scanPython(rel, file, findings, autoMapRefs) {
  const text = fs.readFileSync(file, 'utf8');
  const caps = [];
  const lines = text.split('\n');
  for (const [cap, re] of PY_CAPS) {
    const g = new RegExp(re.source, 'gm');
    let m;
    while ((m = g.exec(text))) {
      const line = text.slice(0, m.index).split('\n').length;
      if (!caps.some((c) => c.cap === cap && c.line === line)) caps.push({ cap, line, code: lines[line - 1].trim().slice(0, 120) });
      if (caps.length > 20) break;
    }
  }
  const referenced = autoMapRefs.has(path.basename(file));
  findings.push({
    severity: referenced || caps.length ? 'high' : 'medium',
    rule: 'python-code',
    file: rel,
    where: null,
    message: `Python file in model directory${referenced ? ' (referenced by auto_map)' : ''}; runs if loaded with trust_remote_code=True${caps.length ? `; uses ${[...new Set(caps.map((c) => c.cap))].join(', ')}` : ''}`,
    evidence: caps.slice(0, 5).map((c) => `L${c.line}: ${c.code}`).join(' | ') || null,
  });
  for (const url of urlsIn(text)) findings.push({ severity: 'medium', rule: 'url-in-code', file: rel, where: null, message: 'URL in model Python code', evidence: url });
}

function scanGguf(rel, file, findings) {
  let meta;
  try {
    meta = readGgufMetadata(file).metadata;
  } catch (e) {
    findings.push({ severity: 'info', rule: 'gguf-unreadable', file: rel, where: null, message: `could not read GGUF metadata: ${e.message}`, evidence: null });
    return;
  }
  for (const [key, value] of Object.entries(meta)) {
    if (typeof value !== 'string') continue;
    findings.push(...urlFindings(rel, key, value, { template: isTemplateKey(key) }));
  }
}

function scanSafetensors(rel, file, findings) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const len = Buffer.alloc(8);
    fs.readSync(fd, len, 0, 8, 0);
    const n = Number(len.readBigUInt64LE(0));
    if (n <= 0 || n > 100 * 1024 * 1024) return;
    const header = Buffer.alloc(n);
    fs.readSync(fd, header, 0, n, 8);
    const meta = JSON.parse(header.toString('utf8')).__metadata__ || {};
    for (const s of jsonStrings(meta, ['__metadata__'])) findings.push(...urlFindings(rel, s.path, s.value, { template: false }));
  } catch {
    // not our problem: malformed headers are reported by the loader
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

// Ollama keeps manifests (JSON) that say which blob is the template, licence, etc.
function ollamaBlobTypes(files) {
  const types = new Map();
  for (const { file, size } of files) {
    if (!file.split(path.sep).includes('manifests') || size > 1024 * 1024) continue;
    try {
      const m = JSON.parse(fs.readFileSync(file, 'utf8'));
      for (const layer of m.layers || []) {
        if (layer.digest && layer.mediaType) types.set(layer.digest.replace(':', '-'), layer.mediaType);
      }
    } catch {}
  }
  return types;
}

function isText(buf) {
  if (buf.includes(0)) return false;
  return !buf.toString('utf8').includes('\uFFFD');
}

export function scanModelDir(root, { env = null } = {}) {
  const abs = path.resolve(root);
  const st = fs.statSync(abs);
  const files = st.isDirectory() ? walk(abs) : [{ file: abs, size: st.size }];
  const base = st.isDirectory() ? abs : path.dirname(abs);
  const findings = [];
  const autoMapRefs = new Set();
  const blobTypes = ollamaBlobTypes(files);
  const counted = { files: files.length, gguf: 0, json: 0, python: 0 };

  // JSON first so auto_map references are known when we reach the .py files.
  const order = (f) => (f.file.endsWith('.json') ? 0 : f.file.endsWith('.py') ? 1 : 2);
  for (const f of [...files].sort((a, b) => order(a) - order(b) || a.file.localeCompare(b.file))) {
    const rel = path.relative(base, f.file) || path.basename(f.file);
    const ext = path.extname(f.file).toLowerCase();
    const name = path.basename(f.file);
    if (ext === '.json' && f.size <= MAX_TEXT) {
      counted.json++;
      scanJson(rel, f.file, findings, autoMapRefs);
    } else if (ext === '.py') {
      counted.python++;
      scanPython(rel, f.file, findings, autoMapRefs);
    } else if (ext === '.jinja' || ext === '.j2' || /template/i.test(name)) {
      if (f.size <= MAX_TEXT) findings.push(...urlFindings(rel, null, fs.readFileSync(f.file, 'utf8'), { template: true }));
    } else if (ext === '.safetensors') {
      scanSafetensors(rel, f.file, findings);
    } else if (ext === '.gguf' || isGguf(f.file)) {
      counted.gguf++;
      scanGguf(rel, f.file, findings);
    } else if (PICKLE_EXT.has(ext) && f.size > 0) {
      findings.push({ severity: 'medium', rule: 'pickle-weights', file: rel, where: null, message: 'pickle-based weights can run code when loaded (prefer .safetensors, or torch.load(weights_only=True))', evidence: null });
    } else if (/^sha256-[0-9a-f]{64}$/.test(name) && f.size <= 1024 * 1024) {
      const buf = fs.readFileSync(f.file);
      if (!isText(buf)) continue;
      const type = blobTypes.get(name) || '';
      if (/license/.test(type)) continue;
      findings.push(...urlFindings(rel, type || null, buf.toString('utf8'), { template: /template/.test(type) }));
    }
  }

  if (env) {
    const unset = checkEnv(env).filter((r) => !r.ok);
    if (unset.length) {
      findings.push({ severity: 'info', rule: 'telemetry-env-unset', file: '(environment)', where: null, message: `${unset.length} documented telemetry/offline switches are not set in this shell (see: phonehome env)`, evidence: unset.map((r) => r.name).join(', ') });
    }
  }

  findings.sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity) || a.file.localeCompare(b.file));
  const counts = Object.fromEntries(SEVERITY.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  return { root: abs, scanned: counted, counts, findings };
}

export function failsAt(result, level) {
  if (level === 'none') return false;
  const idx = SEVERITY.indexOf(level);
  return result.findings.some((f) => SEVERITY.indexOf(f.severity) <= idx);
}

export function renderScan(result) {
  const out = [`phonehome scan: ${result.root}`, `scanned ${result.scanned.files} files (${result.scanned.json} JSON, ${result.scanned.python} Python, ${result.scanned.gguf} GGUF)`, ''];
  for (const f of result.findings) {
    out.push(`${f.severity.toUpperCase().padEnd(6)} ${f.rule}  ${f.file}${f.where ? ` (${f.where})` : ''}`);
    out.push(`       ${f.message}`);
    if (f.evidence) out.push(`       ${f.evidence}`);
  }
  if (result.findings.length) out.push('');
  const c = result.counts;
  out.push(`${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info`);
  return out.join('\n');
}
