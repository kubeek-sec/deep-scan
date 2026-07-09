# Guinea Pig - security scanner test bed

A **deliberately-vulnerable** fixture project used to evaluate the monorepo's
security scanners. Every planted flaw is recorded in
[`expected_findings.json`](expected_findings.json), the single source of truth
for evaluation. Run a scanner against this directory and diff its output against
that file to measure **recall** (planted vulns detected) and **precision**
(false-positive traps that must stay clean).

> All secrets here are **fake**. All vulnerable code is **inert fixture code** -
> nothing is wired into the real application. The only runnable component is the
> DAST target in `dynamic/`, which binds loopback only (see warnings below).

## Layout & modules

| Module dir | Family | What it contains |
|---|---|---|
| `src/python/`, `src/javascript/` | **sast** | Vulnerable source per language; three Python files have a `*_patched.py` sibling used as false-positive traps. |
| `deps/` | **sca** | Dependency manifests (`requirements.txt`, `package.json`) pinned to versions with known CVEs. **Never installed.** |
| `secrets/` | **secret** | `.env`, `config.ini`, a throwaway `service-account.pem`, plus `false_positives.txt` of benign look-alikes. |
| `infra/` | **iac** | `main.tf`, `pod.yaml`, `Dockerfile` with misconfigurations. |
| `ci/` | **pipeline** | `github-workflow.yml` + `gitlab-ci.yml`. Placed in `ci/`, **not** `.github/workflows/`, so the repo's own CI never runs them - point scanners at this dir explicitly. |
| `dynamic/` | **dast** | Runnable stdlib-only HTTP target on `127.0.0.1:3000`. |
| `skill/` | **malware** / **sast** | A deliberately-malicious agent skill (`SKILL.md` + `scripts/summarize.py`): prompt injection, tool poisoning, exfiltration, hidden instructions in invisible/bidi Unicode, and a command-injection helper. Flags `yara` + `mcp-threats` (malware) and `cisco-ai-skill-scanner` (sast). |
| `malware/` | **malware** | `eicar.txt` - the harmless EICAR antivirus test signature the `clamav` scanner flags. |

Every fixture file begins with a header comment listing its CWE id(s), a one-line
description of the flaw, and the expected detecting scanner family.

## Running the dynamic (DAST) target

```bash
python3 dynamic/server.py    # zero dependencies; binds 127.0.0.1:3000
```

See [`dynamic/README.md`](dynamic/README.md) for the route table and manual
proof commands.

### Isolation warnings

- **Loopback only.** The server binds `127.0.0.1`. Never expose it to a network
  or place it behind a public proxy - every route is intentionally exploitable
  (XSS, SQLi, command injection, path traversal, open redirect, SSRF).
- **No real data.** It seeds an in-memory SQLite table with fake users. Do not
  connect it to any real database, credential, or service.
- **Tear down after scanning.** Stop the process (Ctrl-C) as soon as the scan is
  done; do not leave it running.

## Opensource projects for reference scans

| Langage | Simple | Middle | Complexe |
|---------|--------|-------|----------|
| **Python** | [pallets/flask](https://github.com/pallets/flask) | [fastapi/fastapi](https://github.com/fastapi/fastapi) | [django/django](https://github.com/django/django) |
| **JS / TS (+.vue)** | [expressjs/express](https://github.com/expressjs/express) | [element-plus/element-plus](https://github.com/element-plus/element-plus) | [microsoft/vscode](https://github.com/microsoft/vscode) |
| **Go** | [spf13/cobra](https://github.com/spf13/cobra) | [gohugoio/hugo](https://github.com/gohugoio/hugo) | [kubernetes/kubernetes](https://github.com/kubernetes/kubernetes) |
| **Rust** | [sharkdp/fd](https://github.com/sharkdp/fd) | [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep) | [tokio-rs/tokio](https://github.com/tokio-rs/tokio) |
| **Java** | [google/gson](https://github.com/google/gson) | [square/okhttp](https://github.com/square/okhttp) | [spring-projects/spring-framework](https://github.com/spring-projects/spring-framework) |
| **C / C++** | [DaveGamble/cJSON](https://github.com/DaveGamble/cJSON) | [redis/redis](https://github.com/redis/redis) | [llvm/llvm-project](https://github.com/llvm/llvm-project) |
| **Ruby** | [sinatra/sinatra](https://github.com/sinatra/sinatra) | [jekyll/jekyll](https://github.com/jekyll/jekyll) | [rails/rails](https://github.com/rails/rails) |
| **C#** | [DapperLib/Dapper](https://github.com/DapperLib/Dapper) | [dotnet/efcore](https://github.com/dotnet/efcore) | [dotnet/roslyn](https://github.com/dotnet/roslyn) |
| **PHP (+blade)** | [slimphp/Slim](https://github.com/slimphp/Slim) | [monicahq/monica](https://github.com/monicahq/monica) | [laravel/framework](https://github.com/laravel/framework) |
| **Bash** | [nvh/nvm](https://github.com/nvm-sh/nvm) | [bats-core/bats-core](https://github.com/bats-core/bats-core) | [ohmyzsh/ohmyzsh](https://github.com/ohmyzsh/ohmyzsh) |

Q