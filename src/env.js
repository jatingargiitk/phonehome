// Report which documented telemetry / offline switches are set.
import { OPT_OUT_ENV } from './run.js';

export const ENV_CHECKS = [
  { name: 'HF_HUB_OFFLINE', want: '1', tool: 'huggingface_hub', effect: 'no HTTP calls to the Hugging Face Hub (cache only)' },
  { name: 'HF_HUB_DISABLE_TELEMETRY', want: '1', tool: 'huggingface_hub', effect: 'disables library telemetry' },
  { name: 'TRANSFORMERS_OFFLINE', want: '1', tool: 'transformers', effect: 'load from local files only' },
  { name: 'HF_DATASETS_OFFLINE', want: '1', tool: 'datasets', effect: 'load from local cache only' },
  { name: 'DO_NOT_TRACK', want: '1', tool: 'huggingface_hub, vLLM and other tools that honour it', effect: 'generic telemetry opt-out' },
  { name: 'VLLM_NO_USAGE_STATS', want: '1', tool: 'vLLM', effect: 'disables usage stats reporting' },
  { name: 'VLLM_DO_NOT_TRACK', want: '1', tool: 'vLLM', effect: 'disables usage stats reporting' },
  { name: 'GRADIO_ANALYTICS_ENABLED', want: 'False', tool: 'Gradio', effect: 'disables analytics' },
  { name: 'ANONYMIZED_TELEMETRY', want: 'False', tool: 'Chroma', effect: 'disables anonymized telemetry' },
];

const truthy = (v) => /^(1|true|yes|on)$/i.test(v || '');
const falsy = (v) => /^(0|false|no|off)$/i.test(v || '');

export function checkEnv(env = process.env) {
  return ENV_CHECKS.map((c) => {
    const value = env[c.name];
    const ok = value !== undefined && (truthy(c.want) ? truthy(value) : falsy(value));
    return { ...c, value: value ?? null, ok };
  });
}

export function renderEnv(rows) {
  const out = ['phonehome env: telemetry / offline switches in this shell', ''];
  const w = Math.max(...rows.map((r) => r.name.length));
  for (const r of rows) {
    const state = r.ok ? `ok   (${r.value})` : r.value == null ? 'unset' : `set to ${JSON.stringify(r.value)}`;
    out.push(`${r.ok ? '✓' : '·'} ${r.name.padEnd(w)}  ${state.padEnd(14)} ${r.tool}: ${r.effect}`);
  }
  const missing = rows.filter((r) => !r.ok);
  out.push('');
  if (missing.length) {
    out.push(`${missing.length} of ${rows.length} not set. To set all of them for one traced run: phonehome --opt-out-env -- <command>`);
    out.push('Or export them:');
    for (const r of missing) out.push(`  export ${r.name}=${OPT_OUT_ENV[r.name]}`);
  } else {
    out.push('All switches set.');
  }
  return out.join('\n');
}
