# Crust TUI Demo — records all interactive features as a GIF
# Usage: brew install charmbracelet/tap/vhs && vhs demo.tape
# Prerequisites: build crust first (go build -o ./crust .)

Output demo.gif
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Padding 20

# ─── Phase 1: Banner + Version ───
Type "./crust version"
Enter
Sleep 2s

# ─── Phase 2: Help (styled columns) ───
Type "./crust help"
Enter
Sleep 4s

# ─── Phase 3: Shell Completion (install with spinner) ───
Sleep 1s
Type "./crust completion"
Enter
Sleep 2s

# Uninstall first so --install actually runs the spinner (not "already installed")
Type "./crust completion --uninstall"
Enter
Sleep 2s

Type "./crust completion --install"
Enter
Sleep 3s

# ─── Phase 4: Start with progress bar ───
Type "./crust start --auto"
Enter
Sleep 5s

# ─── Phase 5: Status dashboard (static) ───
Type "./crust status"
Enter
Sleep 2.5s

# ─── Phase 6: Live dashboard (auto-refresh) ───
Type "./crust status --live"
Enter
Sleep 4s
Type "r"
Sleep 2s
Type "q"
Sleep 1s

# ─── Phase 7: Scrollable log viewport ───
Type "./crust logs"
Enter
Sleep 1.5s
Down 5
Sleep 1s
Up 3
Sleep 1s
Type "q"
Sleep 1s

# ─── Phase 8: Interactive rules list + filter ───
Type "./crust list-rules"
Enter
Sleep 2s
Down 3
Sleep 1s
Down 3
Sleep 1s
# Filter by name
Type "/"
Sleep 0.5s
Type "ssh"
Sleep 2s
Escape
Sleep 1s
Type "q"
Sleep 1s

# ─── Phase 9: Stop with spinner glow ───
Type "./crust stop"
Enter
Sleep 3s

# ─── Phase 10: Plain mode comparison ───
Type "NO_COLOR=1 ./crust version"
Enter
Sleep 2s

# ─── Cleanup ───
Type "./crust completion --uninstall"
Enter
Sleep 2s

Type "# Done!"
Enter
Sleep 2s
