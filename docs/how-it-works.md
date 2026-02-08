# How It Works

## Architecture

```
                    REQUEST SIDE                         RESPONSE SIDE
                         │                                    │
Agent Request ──▶ [Layer 0: History Scan] ──▶ LLM ──▶ [Layer 1: Rules] ──▶ Execute
                         │                                    │
                      ↓ BLOCK                              ↓ BLOCK
                   (14-30μs)                             (14-30μs)
               "Bad agent detected"                   "Action blocked"

Layer 1 Rule Evaluation Order:
  1. Operation-based Rules → path/command/host matching for known tools
  2. Fallback Rules (content-only) → raw JSON matching, works for ANY tool
```

**Layer 0 (Request History):** Scans tool_calls in conversation history. Catches "bad agent" patterns where malicious actions already occurred in past turns.

**Layer 1 (Response Rules):** Scans LLM-generated tool_calls in responses. Fast pattern matching with friendly error messages.

---

## Rule Schema (Progressive Disclosure)

```yaml
# Level 1: One-liner
- block: "**/.env"

# Level 2: With exceptions
- block: "**/.env"
  except: "**/.env.example"

# Level 3: With actions
- block: "/etc/**"
  actions: [delete]
  message: "Cannot delete system files"

# Level 4: Advanced match
- name: block-proc-access
  match:
    path: "re:/proc/\\d+/environ"
    tool: [Bash, Read]

# Level 5: Composite (AND/OR)
- name: block-symlink-bypass
  all:
    - command: "re:ln\\s+-s"
    - path: "/etc/**"

# Fallback Rules (Content-only) - matches ANY tool including MCP
- name: block-domain
  match:
    content: "malicious.com"  # Matches raw JSON args
  message: "Cannot access malicious.com"
```

---

## When Each Layer Blocks

| Attack | Layer 0 | Layer 1 |
|--------|---------|---------|
| Bad agent with secrets in history | ✅ Blocked | - |
| Poisoned conversation replay | ✅ Blocked | - |
| LLM generates `cat .env` | - | ✅ Blocked |
| LLM generates `rm -rf /etc` | - | ✅ Blocked |
| `$(cat .env)` obfuscation | - | ✅ Blocked |
| Symlink bypass | - | ✅ Blocked (composite) |
| MCP plugin (e.g. Playwright) | - | ✅ Blocked (content-only) |

---

## Built-in Rule Principles

1. **Protect secrets first** - Credentials are the #1 target; block all access paths
2. **Prevent persistence** - Stop attackers from surviving reboots (cron, systemd, RC files)
3. **Block lateral movement** - Internal networks, cloud metadata, container escapes
4. **Allow legitimate dev work** - Never block normal coding tasks; use exceptions for `.example` files
5. **Fail safe** - When in doubt, block and explain why

---

## Protection Categories (Examples)

The rule engine can protect against various attack vectors:

| Category | Examples |
|----------|----------|
| Credentials | .env, SSH keys, cloud creds, tokens |
| System | Binaries, kernel modules, boot |
| Persistence | Shell RC, cron, systemd, git hooks |
| Privilege Escalation | Sudoers, PAM, LD_PRELOAD |
| Container Escape | Docker/containerd sockets |
| Network | Internal networks, cloud metadata |

See `internal/rules/builtin/security.yaml` for actual built-in rules.

