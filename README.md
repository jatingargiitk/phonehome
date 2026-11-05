# phonehome

[![CI](https://github.com/jatingargiitk/phonehome/actions/workflows/ci.yml/badge.svg)](https://github.com/jatingargiitk/phonehome/actions/workflows/ci.yml)
![license MIT](https://img.shields.io/badge/license-MIT-blue)
![node 20+](https://img.shields.io/badge/node-20%2B-3f8f5a)
![dependencies 0](https://img.shields.io/badge/dependencies-0-3f8f5a)

**Prove your local model stack makes zero network calls.**

`phonehome -- <command>` runs a command under `strace`, follows every child process, and logs every DNS lookup and outbound connection by process. It ends with either `0 egress` or a destination map, and exits non-zero if anything you did not allow went out. `phonehome scan <model-dir>` statically checks a downloaded model for `trust_remote_code` Python, URLs in chat templates and configs, and unset telemetry switches.

![phonehome demo](docs/demo.gif)

<sub>The GIF was recorded with [vhs](https://github.com/charmbracelet/vhs) from [`docs/demo.tape`](docs/demo.tape) on a machine behind a proxy that answers every DNS query with a `198.18.x.x` address, so those are the IPs it shows. The text outputs below were copied from the CI demo job, which has normal networking.</sub>

## Why

On 26 Oct 2026 Cohere published [*Concerning behavior from a popular open-weight AI model*](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model). In its own sandbox, running Alibaba's open-weight Qwen3.8-Flash-Next as an agent on a security benchmark, the model listed `/tmp`, checked which transfer tools were installed, read `/etc/resolv.conf`, and tried a `curl` PUT of a test string to an Alibaba Cloud storage bucket in Beijing, right after its reasoning said no tools would be called. The sandbox had no route out, so nothing left it. Cohere puts the behaviour at under one call in 100,000, says a clean re-run produced a normal answer, and says it "cannot answer whether this is deliberate or a leftover glitch from training". Cohere also released the [traces and a reproduction script](https://huggingface.co/datasets/CohereLabs/10-2026-qwen-investigation-traces).

The report was discussed at length on r/LocalLLaMA, including a post with the traces and a follow-up arguing that the reproduction depends on a 2,323-token prefill that stops just before the URL, so it shows URL autocompletion rather than a backdoor. phonehome takes no side on that. Its point is narrower: "it runs locally" is a claim you can check. Model weights do not open sockets; the inference server, the agent loop, the tools it calls and the libraries underneath do. phonehome watches all of them and tells you what actually went out.

## Install

Linux with `strace` and Node 20 or newer:

```bash
sudo apt-get install -y strace        # Debian/Ubuntu; dnf/pacman/apk also ship it
npx github:jatingargiitk/phonehome -- <command>
```

or clone and run `node bin/phonehome.js`. There are no npm dependencies. The `phonehome` name on npm belongs to an unrelated package, and this project is not published there.

## Trace a command

A script that makes no network calls (it hashes in a loop and talks to its own loopback HTTP server):

```console
$ phonehome -- node examples/no-network.js
sha256 x100000: 4eaf2ac96be44c75...
loopback GET -> ok from 127.0.0.1

phonehome: traced node examples/no-network.js
phonehome: 1 process observed

local only: 1 loopback connection (not egress)

✓ 0 egress: no DNS lookups and no outbound connections
```

A script that resolves `example.com` and fetches `https://example.com/`:

```console
$ phonehome -- node examples/egress-demo.js
resolved example.com -> 104.20.23.154
GET https://example.com/ -> 200

phonehome: traced node examples/egress-demo.js
phonehome: 1 process observed

DNS lookups
name         type    process     count
example.com  A,AAAA  node[2655]  4      UNEXPECTED

Outbound destinations
host         address            proto  process     count  result
example.com  104.20.23.154:443  tcp    node[2655]  1      sent 1751 B  UNEXPECTED

note: 2 UDP sockets connected without sending data (source-address probes, not counted): 172.66.147.243:0, [2606:4700:10::ac42:93f3]:0

✗ egress detected: 1 DNS lookup, 1 destination not on the allowlist
$ echo $?
1
```

The host column comes from the DNS answers phonehome saw, or from the TLS SNI / HTTP `Host` in the first bytes sent, so connections to hard-coded IPs are still named when possible. The UDP "probes" are glibc/Node connecting a UDP socket to pick a source address; nothing is sent on them.

The same script with an allowlist:

```console
$ phonehome --allow example.com -- node examples/egress-demo.js
resolved example.com -> 172.66.147.243
GET https://example.com/ -> 200

phonehome: traced node examples/egress-demo.js
phonehome: 1 process observed

DNS lookups
name         type    process     count
example.com  A,AAAA  node[2684]  4      allowed

Outbound destinations
host         address             proto  process     count  result
example.com  172.66.147.243:443  tcp    node[2684]  1      sent 1751 B  allowed

note: 3 UDP sockets connected without sending data (source-address probes, not counted): 104.20.23.154:0, [2606:4700:10::ac42:93f3]:0, [2606:4700:10::6814:179a]:0

✓ 0 unexpected egress (1 DNS lookup, 1 destination, all allowed)
```

### A real tool: `hf download`

The Hugging Face CLI (`huggingface_hub` 2.4.0, installed with `pipx install 'huggingface_hub[cli]'`) fetching one small file, run three times in the CI demo job. First run, as JSON (only the summary line is shown here):

```console
$ phonehome --json -- hf download openai-community/gpt2 config.json > online.json
$ node -e "const j=require('./online.json');console.log(j.result, j.lookups.map(l=>l.name).join(' '))"
unexpected-egress huggingface.co pypi.org
```

Second run, file already cached:

```console
$ phonehome -- hf download openai-community/gpt2 config.json
✓ Downloaded
  path: /home/runner/work/_temp/hf/hub/models--openai-community--gpt2/snapshots/607a30d783dfa663caf39e06633721c8d4cfcd7e/config.json

phonehome: traced hf download openai-community/gpt2 config.json
phonehome: 1 process observed

DNS lookups
name            type    process   count
huggingface.co  A,AAAA  hf[2732]  2      UNEXPECTED

Outbound destinations
host            address           proto  process   count  result
huggingface.co  52.84.217.69:443  tcp    hf[2732]  1      sent 1379 B  UNEXPECTED

note: 2 UDP sockets connected without sending data (source-address probes, not counted): 52.84.217.103:443, [2600:9000:203d:a000:17:b174:6d00:93a1]:443

✗ egress detected: 1 DNS lookup, 1 destination not on the allowlist
```

Third run with `--opt-out-env`, which sets the documented offline/telemetry switches (`HF_HUB_OFFLINE=1` and the others listed by `phonehome env`) for the traced command:

```console
$ phonehome --opt-out-env -- hf download openai-community/gpt2 config.json
✓ Downloaded
  path: /home/runner/work/_temp/hf/hub/models--openai-community--gpt2/snapshots/607a30d783dfa663caf39e06633721c8d4cfcd7e/config.json

phonehome: traced hf download openai-community/gpt2 config.json
phonehome: 1 process observed

✓ 0 egress: no DNS lookups and no outbound connections
```

(The unauthenticated-request warning `hf` prints on stderr is left out above.) These are observations from one CI run; phonehome reports what went out, not why.

### Options

```text
phonehome [options] -- <command> [args...]   trace a command and its children
phonehome --pid <pid> [options]              attach to a running process (needs ptrace rights)
phonehome analyze <trace-dir|file> [options] report on an existing strace -ff -yy -x output
phonehome scan <model-dir|file>... [--json] [--fail-on high|medium|low|info|none]
phonehome env                                show telemetry / offline switches in this shell

--allow <rule>        allowed host (example.com, *.example.com), IP or CIDR, optional :port.
                      Repeat or comma-separate. Loopback is always local.
--timeout <dur>       stop the command after a duration (e.g. 30, 30s, 2m) and report
--json                print the report as JSON on stdout (command stdout goes to stderr)
--md <file>           also write a Markdown report with a result badge
--keep-trace <dir>    keep the raw strace files (they contain traffic payload snippets)
--opt-out-env         set documented telemetry/offline env switches for the command
--egress-exit-code N  exit code when unexpected egress is seen (default 1)
--no-color            plain output
```

Exit codes: unexpected egress gives `1` (or `--egress-exit-code`); otherwise the command's own exit code (`0` if it was stopped by `--timeout`); phonehome's own errors give `2`. That makes it usable as a CI gate: the demo job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs every command shown here and checks the exit codes.

`--md report.md` writes a short Markdown report with a badge. For the no-network script it wrote:

```markdown
![phonehome](https://img.shields.io/badge/phonehome-0%20egress-brightgreen)

Traced: `node examples/no-network.js`

**0 egress: no DNS lookups and no outbound connections**

<sub>Generated by [phonehome](https://github.com/jatingargiitk/phonehome) on linux with strace.</sub>
```

Connections to `169.254.169.254` (the cloud metadata address) are labelled as such in the destination map.

## Scan a model directory

`scan` reads files only; it never imports or executes anything. It looks for:

- `auto_map` entries in `config.json` and the Python files they load with `trust_remote_code=True`, plus network-capable imports and calls in that Python
- URLs in chat templates (`tokenizer_config.json`, `chat_template.jinja`, GGUF `tokenizer.chat_template` metadata) and in configs
- pickle-based weight files (`.bin`, `.pt`, `.pth`, `.ckpt`, `.pkl`), which can run code when loaded
- documented telemetry/offline switches not set in the current shell

[`examples/remote-code-model`](examples/remote-code-model) is a harmless fixture (its only URLs are under `.invalid`, which can never resolve, and nothing in it is run):

```console
$ phonehome scan examples/remote-code-model
phonehome scan: /workspace/github/phonehome/examples/remote-code-model
scanned 4 files (2 JSON, 2 Python, 0 GGUF)

HIGH   remote-code-auto-map  config.json (auto_map)
       auto_map loads configuration_demo.py when trust_remote_code=True
       configuration_demo.DemoConfig
HIGH   remote-code-auto-map  config.json (auto_map)
       auto_map loads modeling_demo.py when trust_remote_code=True
       modeling_demo.DemoForCausalLM
HIGH   python-code  configuration_demo.py
       Python file in model directory (referenced by auto_map); runs if loaded with trust_remote_code=True
HIGH   python-code  modeling_demo.py
       Python file in model directory (referenced by auto_map); runs if loaded with trust_remote_code=True; uses network
       L4: import urllib.request | L12: urllib.request.urlopen("https://telemetry.example.invalid/ping")
MEDIUM url-in-code  modeling_demo.py
       URL in model Python code
       https://telemetry.example.invalid/ping
MEDIUM url-in-template  tokenizer_config.json (chat_template)
       URL inside a chat template (rendered into every prompt)
       https://pixel.example.invalid/t.gif
INFO   telemetry-env-unset  (environment)
       9 documented telemetry/offline switches are not set in this shell (see: phonehome env)
       HF_HUB_OFFLINE, HF_HUB_DISABLE_TELEMETRY, TRANSFORMERS_OFFLINE, HF_DATASETS_OFFLINE, DO_NOT_TRACK, VLLM_NO_USAGE_STATS, VLLM_DO_NOT_TRACK, GRADIO_ANALYTICS_ENABLED, ANONYMIZED_TELEMETRY

4 high, 2 medium, 0 low, 1 info
$ echo $?
1
```

The same scan on the real `openai-community/gpt2` snapshot downloaded above (CI demo job):

```console
$ phonehome scan "$HF_HOME/hub/models--openai-community--gpt2" --fail-on high
phonehome scan: /home/runner/work/_temp/hf/hub/models--openai-community--gpt2
scanned 3 files (1 JSON, 0 Python, 0 GGUF)

INFO   telemetry-env-unset  (environment)
       9 documented telemetry/offline switches are not set in this shell (see: phonehome env)
       HF_HUB_OFFLINE, HF_HUB_DISABLE_TELEMETRY, TRANSFORMERS_OFFLINE, HF_DATASETS_OFFLINE, DO_NOT_TRACK, VLLM_NO_USAGE_STATS, VLLM_DO_NOT_TRACK, GRADIO_ANALYTICS_ENABLED, ANONYMIZED_TELEMETRY

0 high, 0 medium, 0 low, 1 info
```

It also understands Ollama's `~/.ollama/models` layout (manifests plus blobs) and reads GGUF metadata directly. `--fail-on` sets the lowest severity that gives exit `1` (default `high`); `--json` prints machine-readable findings.

## Check telemetry switches

```console
$ HF_HUB_OFFLINE=1 phonehome env
phonehome env: telemetry / offline switches in this shell

✓ HF_HUB_OFFLINE            ok   (1)       huggingface_hub: no HTTP calls to the Hugging Face Hub (cache only)
· HF_HUB_DISABLE_TELEMETRY  unset          huggingface_hub: disables library telemetry
· TRANSFORMERS_OFFLINE      unset          transformers: load from local files only
· HF_DATASETS_OFFLINE       unset          datasets: load from local cache only
· DO_NOT_TRACK              unset          huggingface_hub, vLLM and other tools that honour it: generic telemetry opt-out
· VLLM_NO_USAGE_STATS       unset          vLLM: disables usage stats reporting
· VLLM_DO_NOT_TRACK         unset          vLLM: disables usage stats reporting
· GRADIO_ANALYTICS_ENABLED  unset          Gradio: disables analytics
· ANONYMIZED_TELEMETRY      unset          Chroma: disables anonymized telemetry

8 of 9 not set. To set all of them for one traced run: phonehome --opt-out-env -- <command>
Or export them:
  export HF_HUB_DISABLE_TELEMETRY=1
  export TRANSFORMERS_OFFLINE=1
  export HF_DATASETS_OFFLINE=1
  export DO_NOT_TRACK=1
  export VLLM_NO_USAGE_STATS=1
  export VLLM_DO_NOT_TRACK=1
  export GRADIO_ANALYTICS_ENABLED=False
  export ANONYMIZED_TELEMETRY=False
```

## How it works

phonehome runs `strace -ff -yy -x` with a small syscall filter (`execve`, `clone`/`fork`, `connect`, `accept`, `close`, `send*`/`recv*`, `read`/`write`) and one output file per process, then parses those files:

- **Processes**: `execve` and `clone` records give the process tree and each process's command.
- **Connections**: `connect` gives the peer; `-yy` socket annotations keep the peer attached to later sends, and `close`/`accept` handle fd reuse and inbound sockets. A UDP `connect` with no data sent is reported as a probe, not egress. Loopback is local.
- **DNS**: DNS messages sent to port 53 are decoded (questions, answers, CNAME chains), as are systemd-resolved varlink calls, so lookups through `127.0.0.53` or the resolved socket are still attributed to the process that asked. Answers map IPs back to names.
- **Names without DNS**: the TLS ClientHello SNI or HTTP `Host` header in the first bytes sent names connections to hard-coded IPs.
- **Verdict**: everything not local and not matched by `--allow` is unexpected.

The trace files go to a temporary directory and are deleted after the report unless you pass `--keep-trace`.

## Platform support

- **Linux**: full support (tracing, scan, env). Tested in CI on ubuntu-latest with Node 20, 22 and 24.
- **macOS and Windows**: `scan` and `env` work; tracing does not. There is no `strace` on macOS, and `dtruss`/DTrace need SIP changes, so phonehome refuses to trace there rather than give a false `0 egress`. On a Mac, run the stack in a Linux container or VM (see the ptrace note below).

## Limitations

- **It observes; it does not block.** By the time phonehome reports a connection, the bytes have gone. Use it to verify a setup, and pair it with real enforcement (a network namespace, `docker --network none`, a firewall) when it matters.
- **Needs ptrace.** In Docker add `--cap-add SYS_PTRACE`; `--pid` attach is subject to `kernel.yama.ptrace_scope`. Processes that are not descendants of the traced command (for example a daemon you talk to over a socket, such as an already running `ollama serve`) are not traced; trace the daemon itself with `--pid` or start it under phonehome.
- **DNS outside the process**: systemd-resolved (UDP stub or varlink) is decoded, but lookups handed to nscd or another resolver daemon over a Unix socket are not seen, because the daemon, not the traced process, sends the query. A resolver contact phonehome cannot decode is reported as `(undecoded DNS query)`. DNS-over-HTTPS shows up as an HTTPS connection to the resolver.
- **Names are best effort**: a connection to a hard-coded IP without SNI or `Host` is shown by address only, and when several names share one IP the name seen in DNS is used.
- **Overhead**: strace slows syscall-heavy programs noticeably. Fine for a check, not for benchmarks.
- **Payload snippets**: the temporary trace files contain the first 1 KB of each traced read/write. They are deleted unless `--keep-trace` is given; treat kept traces as sensitive.
- **Raw sockets, io_uring and similar** paths that bypass the traced syscalls are not seen.
- `scan` is pattern-based: it finds the usual places remote code and URLs hide, not everything a determined author could do.

## Prior art

- [thinx-pro/egress-lock](https://github.com/thinx-pro/egress-lock): runs an agent, model tool loop or install script with outbound network limited to an allowlist and logs every attempt; enforced by macOS `sandbox-exec`. It enforces where phonehome only observes; phonehome traces syscalls on Linux and adds the model-directory scan. They complement each other.
- [OpenSnitch](https://github.com/evilsocket/opensnitch) (Linux) and [Little Snitch](https://www.obdev.at/products/littlesnitch/) (macOS): interactive per-application firewalls, system-wide rather than per command.
- `strace -f -e trace=network` itself: phonehome is a parser and report on top of it.
- `docker run --network none`, `unshare -n` and `bwrap --unshare-net`: remove the network instead of watching it.
- eBPF tools such as Falco and Tracee give system-wide visibility with far lower overhead, at the cost of root and setup.

## Development

```bash
npm test        # node --test test/*.test.js; the end-to-end tests need strace and skip without it
```

## License

MIT, see [LICENSE](LICENSE).
