import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scanModelDir, failsAt, renderScan } from '../src/scan.js';
import { writeGguf, readGgufMetadata, isGguf } from '../src/gguf.js';

const bin = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'phonehome.js');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'ph-scan-'));
const write = (dir, rel, content) => {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), content);
};
const rules = (r) => r.findings.map((f) => `${f.severity} ${f.rule} ${f.file}`);

function hfRemoteCodeDir() {
  const d = tmp();
  write(d, 'config.json', JSON.stringify({
    architectures: ['DemoForCausalLM'],
    auto_map: { AutoConfig: 'configuration_demo.DemoConfig', AutoModelForCausalLM: 'modeling_demo.DemoForCausalLM', AutoTokenizer: ['other-org/helper--tokenization_x.XTokenizer', null] },
    _name_or_path: 'https://huggingface.co/demo/demo',
  }));
  write(d, 'tokenizer_config.json', JSON.stringify({
    chat_template: "{{ bos_token }}{% for m in messages %}{{ m.content }}{% endfor %} see https://collect.example.net/t?id=1",
    model: { vocab: { 'http://ignored.example': 1 } },
  }));
  write(d, 'generation_config.json', JSON.stringify({ trust_remote_code: true, docs: 'https://docs.example.org/gen' }));
  write(d, 'modeling_demo.py', 'import torch\nimport requests\n\ndef f():\n    return requests.post("https://collect.example.net/v1", json={})\n');
  write(d, 'configuration_demo.py', 'class DemoConfig: pass\n');
  write(d, 'helper.py', 'x = 1\n');
  write(d, 'pytorch_model.bin', 'PK\x03\x04 not really a pickle');
  const header = Buffer.from(JSON.stringify({ __metadata__: { format: 'pt', note: 'mirror at http://weights.example.com/x' } }));
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(header.length));
  write(d, 'model.safetensors', Buffer.concat([len, header]));
  return d;
}

test('scan flags remote code, Python capabilities, template URLs and pickle weights', () => {
  const r = scanModelDir(hfRemoteCodeDir());
  const got = rules(r);
  for (const want of [
    'high remote-code-auto-map config.json',
    'high remote-code-other-repo config.json',
    'high python-code modeling_demo.py',
    'high python-code configuration_demo.py',
    'medium python-code helper.py',
    'medium url-in-template tokenizer_config.json',
    'medium url-in-code modeling_demo.py',
    'medium trust-remote-code-set generation_config.json',
    'medium pickle-weights pytorch_model.bin',
    'low url-in-config generation_config.json',
    'low url-in-config model.safetensors',
    'info source-link config.json',
  ]) assert.ok(got.includes(want), `missing: ${want}\n${got.join('\n')}`);
  assert.ok(!r.findings.some((f) => f.evidence === 'http://ignored.example'), 'vocab is skipped');
  const py = r.findings.find((f) => f.file === 'modeling_demo.py' && f.rule === 'python-code');
  assert.match(py.message, /network/);
  assert.match(py.evidence, /L2: import requests/);
  assert.equal(failsAt(r, 'high'), true);
  assert.match(renderScan(r), /HIGH +remote-code-auto-map/);
});

test('a plain safetensors model is clean', () => {
  const d = tmp();
  write(d, 'config.json', JSON.stringify({ architectures: ['LlamaForCausalLM'], hidden_size: 64 }));
  write(d, 'tokenizer_config.json', JSON.stringify({ chat_template: '{% for m in messages %}{{ m.content }}{% endfor %}' }));
  const r = scanModelDir(d);
  assert.deepEqual(r.findings, []);
  assert.equal(failsAt(r, 'info'), false);
});

test('GGUF metadata round-trips and template URLs inside GGUF are found', () => {
  const d = tmp();
  const f = path.join(d, 'tiny.gguf');
  writeGguf(f, {
    'general.architecture': 'llama',
    'general.license.link': 'https://example.org/license',
    'llama.context_length': 2048,
    'tokenizer.ggml.tokens': ['<s>', '</s>', 'a'],
    'tokenizer.chat_template': '{{ messages }} <img src="https://pixel.example.com/p.gif">',
  });
  assert.equal(isGguf(f), true);
  const meta = readGgufMetadata(f).metadata;
  assert.equal(meta['general.architecture'], 'llama');
  assert.equal(meta['llama.context_length'], 2048);
  const r = scanModelDir(d);
  assert.deepEqual(rules(r).sort(), ['info source-link tiny.gguf', 'medium url-in-template tiny.gguf']);
  assert.equal(r.scanned.gguf, 1);
});

test('Ollama store: blobs typed by manifest, GGUF blob read, licence blob skipped', () => {
  const d = tmp();
  const ggufDigest = 'a'.repeat(64);
  const tmplDigest = 'b'.repeat(64);
  const licDigest = 'c'.repeat(64);
  fs.mkdirSync(path.join(d, 'blobs'));
  writeGguf(path.join(d, 'blobs', `sha256-${ggufDigest}`), { 'general.architecture': 'qwen2', 'general.name': 'tiny' });
  write(d, `blobs/sha256-${tmplDigest}`, '{{ .Prompt }} https://beacon.example.com/');
  write(d, `blobs/sha256-${licDigest}`, 'Licence text https://example.com/licence');
  write(d, 'manifests/registry.ollama.ai/library/tiny/latest', JSON.stringify({
    layers: [
      { mediaType: 'application/vnd.ollama.image.model', digest: `sha256:${ggufDigest}` },
      { mediaType: 'application/vnd.ollama.image.template', digest: `sha256:${tmplDigest}` },
      { mediaType: 'application/vnd.ollama.image.license', digest: `sha256:${licDigest}` },
    ],
  }));
  const r = scanModelDir(d);
  assert.equal(r.scanned.gguf, 1);
  assert.deepEqual(r.findings.map((f) => [f.rule, f.evidence]), [['url-in-template', 'https://beacon.example.com/']]);
});

test('scan CLI: exit code follows --fail-on, --json parses', () => {
  const d = hfRemoteCodeDir();
  const r = spawnSync(process.execPath, [bin, 'scan', d, '--json'], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.ok(JSON.parse(r.stdout).counts.high >= 4);
  assert.equal(spawnSync(process.execPath, [bin, 'scan', d, '--fail-on', 'none'], { encoding: 'utf8' }).status, 0);
  const env = { ...process.env, HF_HUB_DISABLE_TELEMETRY: '' };
  const withEnv = spawnSync(process.execPath, [bin, 'scan', d], { encoding: 'utf8', env });
  assert.match(withEnv.stdout, /telemetry-env-unset/);
  assert.match(withEnv.stdout, /HF_HUB_DISABLE_TELEMETRY/);
});
