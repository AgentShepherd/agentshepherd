#!/bin/bash
# generate-demo-gif.sh — Regenerate docs/demo.gif when TUI files change.
# Used as a pre-push hook. Requires vhs to be installed.
set -euo pipefail

# Check if any TUI-related files are in the staged diff vs origin
TUI_CHANGED=$(git diff --name-only origin/main...HEAD -- \
    'internal/tui/**/*.go' \
    'internal/logger/logger.go' \
    'scripts/demo.tape' \
    'scripts/demo-attack.sh' \
    2>/dev/null || true)

if [ -z "$TUI_CHANGED" ]; then
    echo "demo-gif: no TUI changes detected, skipping"
    exit 0
fi

echo "demo-gif: TUI changes detected in:"
echo "$TUI_CHANGED" | sed 's/^/  /'

# Require vhs
if ! command -v vhs &>/dev/null; then
    echo "demo-gif: ERROR: vhs is required but not installed"
    echo "demo-gif: Install with: brew install charmbracelet/tap/vhs"
    exit 1
fi

# Build crust
echo "demo-gif: building crust..."
go build -o ./crust .

# Generate the GIF
echo "demo-gif: generating docs/demo.gif..."
vhs scripts/demo.tape

echo "demo-gif: docs/demo.gif updated"
# Remind to commit if changed
if ! git diff --quiet docs/demo.gif 2>/dev/null; then
    echo "demo-gif: demo.gif changed — don't forget to commit it"
fi
