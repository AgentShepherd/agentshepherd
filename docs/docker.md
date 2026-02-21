# Docker

A [`Dockerfile`](../Dockerfile) is included in the repo.

## Quick Start

```bash
docker build -t crust .
docker run -d -t -p 9090:9090 crust
```

The default entrypoint runs `crust start --foreground --auto --listen-address 0.0.0.0`. Use `-t` for ANSI-styled `docker logs` output.

## docker-compose

With per-provider API keys injected via environment:

```yaml
# docker-compose.yml
services:
  crust:
    build: .
    ports:
      - "9090:9090"
    tty: true
    restart: always
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - crust-data:/root/.crust
      - ./config.yaml:/root/.crust/config.yaml:ro
volumes:
  crust-data:
```

```yaml
# config.yaml — provider keys reference env vars
upstream:
  providers:
    openai:
      url: "https://api.openai.com"
      api_key: "$OPENAI_API_KEY"
```

Point your agents to `http://<docker-host>:9090` instead of `localhost`.

## What Works in Docker

All rule-based blocking, tool call inspection (Layers 0 & 1), content scanning, telemetry, and auto-mode provider resolution. These operate on API traffic passing through the proxy and work regardless of where Crust runs.

## TUI in Docker

Use `-t` for ANSI-styled output (colors, bold, icons) in `docker logs`. Without `-t`, output is plain text. Terminal escape sequence queries are suppressed automatically.

For interactive TUI setup, use `docker run -it --entrypoint crust crust start --foreground` (without `--auto`). Set `NO_COLOR=1` to force plain.

See [tui.md](tui.md) for the full technical breakdown of how foreground mode handles terminal detection in containers.

## Persistent Data

Telemetry and the SQLite database are stored at `/root/.crust/crust.db`. Mount a volume to persist across restarts:

```bash
docker run -d -t -p 9090:9090 -v crust-data:/root/.crust crust
```

If using database encryption (`DB_KEY`), the same key must be provided on every restart.
