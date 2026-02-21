# Configuration

Crust stores configuration in `~/.crust/config.yaml`.

## Example

The most commonly configured fields:

```yaml
server:
  port: 9090
  log_level: info

upstream:
  url: "https://openrouter.ai/api"       # fallback upstream
  timeout: 300
  providers:                               # custom model routing
    my-llama: "http://localhost:11434/v1"  # short form (URL only)
    openai:                                # expanded form (URL + API key)
      url: "https://api.openai.com"
      api_key: "$OPENAI_API_KEY"           # env variable expansion

security:
  enabled: true
  block_mode: remove    # "remove" or "replace"

rules:
  enabled: true
  watch: true           # hot reload on file change
```

See [`config.yaml`](../config.yaml) in the repo root for the full list of fields including `storage`, `api`, `telemetry`, and advanced `security` options.

## Auto Mode

In auto mode (`--auto`), the gateway resolves providers from the model name using a [built-in registry](../internal/proxy/providers.go) (Anthropic, OpenAI, DeepSeek, Gemini, Mistral, Groq, and more). Clients bring their own API keys unless a per-provider `api_key` is configured. User-defined providers take priority.

## Per-Provider API Keys

Providers support both short form (URL only) and expanded form (URL + API key):

```yaml
upstream:
  providers:
    # Short form — clients bring their own keys
    my-llama: "http://localhost:11434/v1"

    # Expanded form — Crust injects the key when the client doesn't send auth
    openai:
      url: "https://api.openai.com"
      api_key: "$OPENAI_API_KEY"
```

API key values support `$VAR` and `${VAR}` environment variable expansion. This is useful for Docker deployments where secrets are injected via environment.

## Block Mode

| Mode | Behavior |
|------|----------|
| `remove` (default) | Dangerous tool calls are silently removed from the request/response |
| `replace` | Dangerous tool calls are replaced with an echo command explaining what was blocked |

Use `replace` to let the agent see block messages and adjust its behavior.
