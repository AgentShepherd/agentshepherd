# Crust Hero Demo — README GIF, optimized for "star in 10 seconds"
# Usage: brew install charmbracelet/tap/vhs && vhs scripts/demo.tape
# Prerequisites: build crust first (task build)

Output docs/demo.gif

# ─── Settings (must come before Env directives) ───
Set FontSize 16
Set FontFamily "Cascadia Mono NF"
Set Width 1200
Set Height 850
Set Framerate 30
Set Theme "GruvboxDark"
Set TypingSpeed 35ms
Set Padding 24
Set LineHeight 1.2
Set Shell bash

# ─── Privacy: anonymous prompt, no username/hostname leak ───
Env PS1 "$ "

# ─── Phase 0: Clean slate + start mock LLM server (hidden) ───
Hide
Type "./crust stop 2>/dev/null; kill $(lsof -ti:18080) 2>/dev/null; sleep 0.3"
Enter
Sleep 0.5s
Type "rm -f ~/.crust/crust.db ~/.crust/crust.db-shm ~/.crust/crust.db-wal"
Enter
Sleep 0.3s
Type "export PATH=.:$PATH"
Enter
Sleep 0.1s
Type "mkdir -p ~/.crust && printf 'upstream:\n  providers:\n    gpt: http://localhost:18080\n' > ~/.crust/config.yaml"
Enter
Sleep 0.1s
Type "python3 scripts/demo-mock.py &>/dev/null &"
Enter
Sleep 0.5s
Type "clear"
Enter
Sleep 0.3s
Show

# ─── Phase 1: Start the gateway (3s) ───
Type "crust start --auto"
Enter
Sleep 3s

# ─── Phase 2: Agent simulation — safe calls + attacks (30s) ───
Type "bash scripts/demo-attack.sh"
Enter
Sleep 30s

# ─── Phase 3: Status dashboard — Overview tab (3s) ───
Type "crust status --live"
Enter
Sleep 3s

# ─── Phase 3b: Switch to Sessions tab — shows 3 concurrent agent sessions (6s) ───
Type "2"
Sleep 2s
Down
Sleep 2s
Down
Sleep 2s

# ─── Phase 4: Clean stop (2s) ───
Type "q"
Sleep 0.5s
Type "crust stop"
Enter
Sleep 2s
