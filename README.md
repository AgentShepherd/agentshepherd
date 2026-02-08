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
  <a href="#features">Features</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="https://github.com/BakeLens/crust/issues">Issues</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go" alt="Go Version" />
  <img src="https://img.shields.io/badge/License-Elastic%202.0-blue.svg" alt="License" />
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey" alt="Platform" />
</p>

## The Problem

AI agents are powerful. They can execute code, read files, make API calls, and interact with your entire system. But with great power comes great risk:

- **Accidental destruction**: `rm -rf /` is just one hallucination away
- **Credential theft**: Agents can read `.env`, SSH keys, and secrets
- **Data exfiltration**: Nothing stops an agent from `curl`-ing your data elsewhere
- **Prompt injection**: Malicious content can hijack agent behavior

**You trust your agents. But should you trust them blindly?**

## The Solution

**Crust** is a transparent gateway that sits between your AI agents and LLM providers. It intercepts every tool call and blocks dangerous actions *before* they happen.

**100% local. Your data never leaves your machine.**

```
Your Agent → Crust → LLM Provider
                  ↓
            🛡️ Security Check
            📊 Telemetry
            ✅ Safe calls pass
            🚫 Dangerous calls blocked
```

## Why Guard Tool Calls?

An LLM by itself is just next-token prediction, but **tool calls make it agentic**. They are the bridge between "thinking" and "doing", and that bridge is exactly where safety matters most.

We specifically monitor **tool call requests**, not responses, because the request is the moment the agent decides to act: execute code, call an API, read your sensitive data, or delete your files. Even when a previous tool call response contains unsafe content, the agent cannot act on it without issuing a new tool call request—meaning every dangerous action must flow through a request we can inspect and block.

By guarding this single chokepoint, Crust catches threats at the point *before* they reach the real world.

<p align="center">
  <img src="docs/crust.png" alt="How Crust works" width="90%" />
</p>

## Quick Start

> **One command. That's it.**

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install.sh)"
```

Then start Crust:

```bash
# Auto mode — clients bring their own auth, provider resolved from model name
crust start --auto

# Or manual mode — single upstream with gateway API key
crust start --endpoint https://api.openai.com/v1 --api-key sk-xxx
```

Point your agent to `http://localhost:9090` instead of the LLM API URL. In auto mode, the gateway routes requests to the correct provider based on the model name and passes through the client's auth header. Done.

## Features

### 🔒 Action Filtering

Block destructive actions with customizable rules (progressive disclosure schema):

```yaml
rules:
  # Simple one-liner
  - block: "**/.env"

  # With exceptions
  - block: "**/.ssh/id_*"
    except: "**/*.pub"

  # Advanced pattern matching
  - name: block-rm-rf
    match:
      command: "re:rm\\s+-rf\\s+/"
    message: "Blocked: destructive command"
```

**Built-in protection against:**
- Credential theft (`.env`, SSH keys, cloud credentials, browser data)
- Shell history exposure (`.bash_history`, `.zsh_history`)
- Persistence vectors (shell RC files, authorized_keys)
- Self-tampering (agents can't disable Crust)
- Private key exfiltration (content-based detection)

### ⚡ Near-Zero Latency

Written in Go for maximum performance. Crust adds very small overhead to your API calls. Your agents won't even notice it's there.

### 🔄 Hot Reload Rules

Add or modify security rules without restarting. Your protection evolves as fast as your threats.

```bash
crust add-rule my-rules.yaml
# Rules active immediately!
```

### 🔌 Universal Compatibility

Works with any agent framework:

- [OpenClaw](https://openclaw.ai/) with customized LLMs
- Claude Code / OpenCode with customized LLMs
- OpenAI/Anthropic Agent SDK with customized LLMs
- LangChain / LangGraph / AutoGPT / AutoGen
- Custom implementations

Just change your API endpoint. No code changes required. In auto mode (`--auto`), the gateway resolves providers from model names and passes through client auth — no need to configure a single upstream or gateway API key.

## How It Works

```
Agent Request ──▶ [Layer 0] ──▶ LLM ──▶ [Layer 1] ──▶ Execute
                     │                      │
                 Scan history           Scan response
                 tool_calls             tool_calls
```

1. **Layer 0 (Request)**: Scans tool_calls in conversation history - catches "bad agent" patterns
2. **Layer 1 (Response)**: Scans LLM-generated tool_calls against security rules

All activity is logged locally to encrypted storage.

## Commands

```bash
# Daemon management
crust start              # Interactive setup
crust start --auto       # Auto mode (resolve provider from model name)
crust start --auto --block-mode replace   # Show block messages to agent (avoid interrupt)
crust start --endpoint URL --api-key KEY  # Manual mode
crust status             # Check if running
crust stop               # Stop the gateway
crust logs [-f]          # View logs (optionally follow)

# Rule management
crust list-rules         # List all active rules
crust add-rule FILE      # Add custom rules
crust remove-rule FILE   # Remove user rules
crust reload-rules       # Hot reload rules

# Other
crust lint-rules [file]  # Validate rule syntax and patterns
crust version            # Show version
crust uninstall          # Complete removal
```

## Configuration

Crust stores configuration in `~/.crust/`:

```yaml
# config.yaml
server:
  port: 9090
  log_level: info

upstream:
  url: "https://openrouter.ai/api/v1"  # fallback upstream (used when no provider matches)
  timeout: 300
  providers:                             # user-defined model keyword → base URL
    my-llama: "http://localhost:11434/v1"
    my-vllm:  "http://gpu-server:8000/v1"

security:
  enabled: true
  block_mode: remove  # "remove": silently remove blocked tool calls; "replace": replace with echo command showing block message

rules:
  enabled: true
  watch: true  # hot reload
```

### Auto Mode (Experimental)

Auto mode (`--auto`) resolves the upstream provider from the `model` field using a built-in registry (e.g., Anthropic, OpenAI, Codex, DeepSeek, Gemini, Mistral, Qwen, Moonshot, Groq, MiniMax, HuggingFace). Clients bring their own auth tokens. User-defined providers in config take priority over builtins. See [providers.go](internal/proxy/providers.go) for the full registry.

## Built-in Rules

Crust ships with battle-tested security rules:

| Category | Protection |
|----------|------------|
| **Credential Theft** | `.env`, SSH keys, cloud credentials, browser passwords |
| **Shell History** | `.bash_history`, `.zsh_history`, command history |
| **Persistence Prevention** | Shell RC files, authorized_keys |
| **Self-Protection** | Crust data directories |
| **Private Key Detection** | Content-based detection of key exfiltration |

## Roadmap

- [ ] **Fine-grained Rules** - More granular control over tool call filtering
- [ ] **Fine-grained Telemetry Analysis** - Currently telemetry is stored with encryption for review only; advanced scanning capabilities coming soon

## Contributing

Crust is an open-source developer tool intended for research, education, and general-purpose agent safety. This project is in active development and we welcome contributions! PRs for customized rules are also welcome.

## Citation

If you use Crust in your research, please cite:

```bibtex
@software{crust2026,
  title = {Crust: A Transparent Gateway for AI Agents},
  author = {Chen, Zichen and Chen, Yuanyuan and Jiang, Bowen and Xu, Zhangchen},
  year = {2026},
  url = {https://github.com/BakeLens/crust}
}
```

## License

Elastic License 2.0 - See [LICENSE](LICENSE) for details.
