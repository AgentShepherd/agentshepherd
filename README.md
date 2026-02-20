<p align="center">
  <img src="docs/banner.png" alt="Crust Banner" width="100%" />
</p>

<h1 align="center">Crust</h1>

<p align="center">
  <strong>Your agents should never <del>(try to)</del> read your secrets.</strong>
</p>

<p align="center">
  <a href="https://getcrust.io">Website</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="https://github.com/BakeLens/crust/issues">Issues</a> •
  <a href="https://github.com/BakeLens/crust/discussions">Discussions</a>
</p>

<p align="center">
  <a href="https://github.com/BakeLens/crust/actions/workflows/ci.yml"><img src="https://github.com/BakeLens/crust/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://goreportcard.com/report/github.com/BakeLens/crust"><img src="https://goreportcard.com/badge/github.com/BakeLens/crust" alt="Go Report Card" /></a>
  <a href="https://github.com/BakeLens/crust/releases"><img src="https://img.shields.io/github/v/release/BakeLens/crust" alt="Release" /></a>
  <img src="https://img.shields.io/github/go-mod/go-version/BakeLens/crust" alt="Go Version" />
  <img src="https://img.shields.io/badge/License-Elastic%202.0-blue.svg" alt="License" />
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows%20%7C%20FreeBSD-lightgrey" alt="Platform" />
</p>

<p align="center">
  <img src="docs/demo.gif" alt="Crust in action" width="800" />
</p>

## What is Crust?

Crust is a transparent, local gateway between your AI agents and LLM providers. It intercepts every tool call — file reads, shell commands, network requests — and blocks dangerous actions before they execute. No code changes required.

**100% local. Your data never leaves your machine.**

## Quick Start

**macOS / Linux:**
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install.sh)"
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/BakeLens/crust/main/install.ps1 | iex
```

Then start the gateway:

```bash
crust start --auto
```

Point your agent to Crust:

| Agent | Configuration |
|-------|---------------|
| **Claude Code** | `ANTHROPIC_BASE_URL=http://localhost:9090` |
| **Codex CLI** | `OPENAI_BASE_URL=http://localhost:9090/v1` |
| **Cursor** | Settings → Models → Override OpenAI Base URL → `http://localhost:9090/v1` |
| **Cline** | Settings → API Configuration → Base URL → `http://localhost:9090/v1` |
| **Windsurf** | Settings → AI → Provider Base URL → `http://localhost:9090/v1` |
| **Open Claw** | Set `baseUrl` to `http://localhost:9090` in `~/.openclaw/openclaw.json` |
| **OpenCode** | `OPENAI_BASE_URL=http://localhost:9090/v1` |
| **Any OpenAI-compatible agent** | Set your LLM base URL to `http://localhost:9090/v1` |

That's it. Crust auto-detects the provider from the model name and passes through your auth. Works with all 7 major coding agents out of the box — each agent's tool names are recognized automatically.

## How It Works

<p align="center">
  <img src="docs/crust.png" alt="Crust architecture" width="90%" />
</p>

Crust inspects tool calls at three layers:

1. **Layer 0 (Request Scan)**: Scans tool calls in conversation history before they reach the LLM — catches agents replaying dangerous actions.
2. **Layer 1 (Response Scan)**: Scans tool calls in the LLM's response before they execute — blocks new dangerous actions in real-time.
3. **Layer 2 (OS Sandbox)**: Kernel-level enforcement via Landlock (Linux) and Seatbelt (macOS) — last line of defense even if rules are bypassed.

All activity is logged locally to encrypted storage.

## Built-in Protection

Crust ships with **14 security rules** out of the box:

| Category | What's Protected |
|----------|-----------------|
| **Credentials** | `.env`, SSH keys, cloud creds (AWS, GCP, Azure), GPG keys |
| **System Auth** | `/etc/passwd`, `/etc/shadow`, sudoers |
| **Shell History** | `.bash_history`, `.zsh_history`, `.python_history`, and more |
| **Browser Data** | Chrome, Firefox, Safari passwords, cookies, local storage |
| **Package Tokens** | npm, pip, Cargo, Composer, NuGet, Gem, Hex auth tokens |
| **Git Credentials** | `.git-credentials`, `.gitconfig` with credentials |
| **Persistence** | Shell RC files, `authorized_keys`, crontabs |
| **Key Exfiltration** | Content-based PEM private key detection |
| **Self-Protection** | Agents cannot read, modify, or disable Crust itself |
| **Dangerous Commands** | `eval`/`exec` with dynamic code execution |

All rules are open source: [`internal/rules/builtin/security.yaml`](internal/rules/builtin/security.yaml)

## Custom Rules

Rules use a progressive disclosure schema — start simple, add complexity only when needed:

```yaml
rules:
  # One-liner: block all .env files
  - block: "**/.env"

  # With exceptions and specific actions
  - block: "**/.ssh/id_*"
    except: "**/*.pub"
    actions: [read, copy]
    message: "Cannot access SSH private keys"

  # Advanced: regex matching on commands
  - name: block-rm-rf
    match:
      command: "re:rm\\s+-rf\\s+/"
    message: "Blocked: recursive delete from root"
```

```bash
crust add-rule my-rules.yaml    # Rules active immediately (hot reload)
```

<details>
<summary><strong>CLI Reference</strong></summary>

```bash
# Gateway
crust start --auto                          # Auto mode (recommended)
crust start --endpoint URL --api-key KEY    # Manual mode
crust start --auto --block-mode replace     # Show block messages to agent
crust start --foreground --auto             # Foreground mode (for Docker)
crust stop                                  # Stop the gateway
crust status                                # Check if running
crust logs [-f]                             # View logs

# Rules
crust list-rules                            # List active rules
crust add-rule FILE                         # Add custom rules (hot reload)
crust remove-rule FILE                      # Remove user rules
crust reload-rules                          # Force reload all rules
crust lint-rules [FILE]                     # Validate rule syntax

# Other
crust version                               # Show version
crust uninstall                             # Complete removal
```

</details>

<details>
<summary><strong>Configuration</strong></summary>

Crust stores configuration in `~/.crust/config.yaml`:

```yaml
server:
  port: 9090
  log_level: info

upstream:
  url: "https://openrouter.ai/api"       # fallback upstream
  timeout: 300
  providers:                               # custom model routing
    my-llama: "http://localhost:11434/v1"
    my-vllm:  "http://gpu-server:8000/v1"

security:
  enabled: true
  block_mode: remove    # "remove" or "replace"

rules:
  enabled: true
  watch: true           # hot reload on file change

sandbox:
  enabled: false        # OS-level sandbox (Landlock/Seatbelt)
```

In auto mode (`--auto`), the gateway resolves providers from the model name using a [built-in registry](internal/proxy/providers.go) (Anthropic, OpenAI, DeepSeek, Gemini, Mistral, Groq, and more). Clients bring their own API keys. User-defined providers take priority.

</details>

<details>
<summary><strong>Docker</strong></summary>

A [`Dockerfile`](Dockerfile) is included in the repo. Build and run:

```bash
docker build -t crust .
docker run -p 9090:9090 crust
```

Or with docker-compose:

```yaml
# docker-compose.yml
services:
  crust:
    build: .
    ports:
      - "9090:9090"
    restart: always
```

Point your agents to `http://<docker-host>:9090` instead of `localhost`.

The `--foreground` flag keeps the process in the foreground so the container stays alive. `--listen-address 0.0.0.0` binds to all interfaces so the host can reach the container.

**What works in Docker:** All rule-based blocking, tool call inspection (Layers 0 & 1), content scanning, and telemetry. These operate on API traffic passing through the proxy and work regardless of where Crust runs.

</details>

<details>
<summary><strong>Build from Source</strong></summary>

Requires Go 1.24+ and [Task](https://taskfile.dev).

```bash
git clone https://github.com/BakeLens/crust.git
cd crust
task build
./crust version
```

</details>

## Contributing

Crust is open-source and in active development. We welcome contributions — PRs for new security rules are especially appreciated.

- [Report a bug](https://github.com/BakeLens/crust/issues)
- [Security vulnerabilities](SECURITY.md) — please report privately
- [Discussions](https://github.com/BakeLens/crust/discussions)

Add this badge to your project's README:

```markdown
[![Protected by Crust](https://img.shields.io/badge/Protected%20by-Crust-blue)](https://github.com/BakeLens/crust)
```

<details>
<summary><strong>Citation</strong></summary>

If you use Crust in your research, please cite:

```bibtex
@software{crust2026,
  title = {Crust: A Transparent Gateway for AI Agent Security},
  author = {Chen, Zichen and Chen, Yuanyuan and Jiang, Bowen and Xu, Zhangchen},
  year = {2026},
  url = {https://github.com/BakeLens/crust}
}
```

</details>

## License

[Elastic License 2.0](LICENSE)
