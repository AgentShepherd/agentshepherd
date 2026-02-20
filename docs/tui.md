# TUI Design

Crust's terminal UI is an optional layer over plain CLI output. Every command works identically with or without it.

## Principles

1. **TUI is invisible when you're not looking.** Styling activates only when stdout is a terminal. Piped output, redirected files, background daemons, and CI all get clean plain text automatically. `NO_COLOR=1` forces plain mode unconditionally. The `notui` build tag removes interactive charmbracelet components (`bubbletea`) at compile time. No feature depends on TUI being present.

2. **One canonical output path.** All user-facing messages go through `PrintSuccess`, `PrintError`, `PrintWarning`, `PrintInfo`. These handle prefix, icon, and plain mode automatically. Never use raw `fmt.Println` for status output.

3. **Styles are data, not functions.** Every `Style*` export is a `lipgloss.Style` variable. Call `.Render()` on them. Capability-aware helpers (`Hyperlink()`, `Faint()`, `Italic()`, `Strikethrough()`, `WindowTitle()`) are functions because they check terminal capabilities before applying styles.

4. **Icons are universal.** All icons use Unicode BMP glyphs (U+2500-U+25CF) that render in every terminal without font installation.

5. **Colors are centralized.** All colors live in `styles.go` as `Color*` adaptive color variables. Styles reference these. No inline `lipgloss.Color()` calls outside `styles.go`. Exception: `banner.go` uses per-character inline styles for gradient rendering, which requires interpolated colors that cannot be pre-defined.

6. **Sub-packages own features, core owns primitives.** `internal/tui/` has styles, icons, print helpers, and columns. `banner/`, `spinner/`, `startup/` are self-contained features that import the core.

7. **Every `_notui.go` mirrors its counterpart.** Same package, same exported API, plain text implementation. Build tags (`//go:build !notui` / `//go:build notui`) select one or the other. They must stay in sync. The `_notui.go` files may import `internal/tui` for print helpers — the core package always compiles regardless of build tags.

8. **Commands offer `--json` for machine consumption.** Commands that produce structured data (`status`, `version`, `list-rules`) support `--json` for scripting and CI integration. JSON output bypasses all TUI styling — no colors, no icons, no prefix.

9. **Interactive components degrade gracefully.** Bubbletea-based interactive components (forms, tables, viewports) fall back to static output in plain mode, piped contexts, and `notui` builds. Interactive mode is opt-in via TTY detection — never block scripted workflows.

10. **Animations serve purpose.** Animations indicate activity (spinner), progress (progress bar), or draw attention (banner reveal, block flash). Every animation can be skipped with a keypress. No decorative-only animations that slow down the user.

## Package Layout

```
internal/tui/
  styles.go         Centralized colors, styles, capability-aware helpers
  icons.go          Unicode BMP icon constants
  print.go          PrintSuccess/Error/Warning/Info with [crust] prefix
  columns.go        AlignColumns() for ANSI-aware two-column alignment
  banner/           Gradient ASCII art banner with reveal animation + RevealLines
  spinner/          Animated dot spinner with success glow effect
  startup/          Interactive huh-based setup wizard with themed forms
  terminal/         Terminal emulator detection and capability bitfield
  progress/         Determinate progress bar for multi-step operations
  dashboard/        Live status dashboard with auto-refreshing metrics
  logview/          Scrollable log viewport with syntax highlighting + block flash
  rulelist/         Interactive filterable rules list with scroll navigation
```

## Plain Mode

Plain mode disables all colors, icons, borders, and animations. It is the default whenever stdout is not an interactive terminal — no ANSI escape codes leak into pipes, redirected files, log files, or CI output.

Detection precedence (evaluated once on first `IsPlainMode()` call):

1. `NO_COLOR=1` environment variable — plain ON ([no-color.org](https://no-color.org))
2. TTY detection — if stdout is not a terminal, plain ON
3. Terminal capability detection — if the emulator is unrecognized and `COLORTERM` is not set, plain ON (TUI is enabled only on supported terminals)
4. `--no-color` CLI flag — calls `tui.SetPlainMode(true)` before any output
5. `notui` build tag — compile-time, removes interactive components (spinner animation, banner reveal)

TUI is enabled by default on all supported emulators listed below. Unrecognized terminals fall back to plain mode automatically. To force TUI on an unlisted terminal, set `COLORTERM=truecolor`.

For scripting and data pipelines, use `--json` on supported commands (`status`, `version`, `list-rules`) to get structured output with no TUI artifacts at all.

Check with `tui.IsPlainMode()` before using any styled output.

## Build Tags

```bash
go build ./...              # Default: full TUI with bubbletea animations
go build -tags notui ./...  # No TUI: removes bubbletea, keeps lipgloss styling
task build                  # Default build
task build-notui            # notui build
```

The `notui` tag removes `bubbletea` and `huh` (interactive framework for spinner, banner, forms, progress, dashboard, log viewer, rule list) from sub-packages via `_notui.go` counterparts. The core `internal/tui/` package (styles, icons, print helpers, columns) always compiles with `lipgloss` — use `NO_COLOR=1` or `--no-color` to disable styling at runtime.

Install scripts support `--no-tui` (bash) or `-NoTUI` (PowerShell).

## Supported Terminals

The TUI uses Unicode BMP characters and ANSI/VT100 sequences with truecolor (24-bit) colors. All visual elements are compatible with the terminals listed below.

### Baseline (OS default)

| OS | Terminal |
|---|---|
| macOS | Terminal.app |
| Linux | GNOME Terminal |
| Linux | Konsole |
| Windows | Windows Terminal |

### Advanced (popular third-party)

| Terminal | Platforms |
|---|---|
| iTerm2 | macOS |
| Alacritty | macOS, Linux, Windows |
| Kitty | macOS, Linux |
| WezTerm | macOS, Linux, Windows |
| foot | Linux (Wayland) |
| Tilix | Linux |

Advanced terminals are a superset of baseline capabilities. Anything that renders on the baseline renders on advanced emulators.

### Visual element compatibility

| Element | Unicode block | Codepoints |
|---|---|---|
| Logo box-drawing | Box Drawings | U+2550–U+256C |
| Border (lipgloss) | Box Drawings | U+256D–U+2570, U+2500, U+2502 |
| Separator bar | Box Drawings | U+2501 |
| Icons (default) | Geometric Shapes | U+25A0–U+25CF |
| Check / Cross | Dingbats | U+2713, U+2717 |
| Block icon | Math Operators | U+2298 |
| Spinner dots | Braille Patterns | U+2800–U+28FF |

All visual elements use BMP codepoints supported by every listed terminal.

Terminals not listed here will likely work if they support VT100 sequences and Unicode BMP. For unsupported or minimal terminals, plain mode (`NO_COLOR=1` or `--no-color`) disables all styling.

### Terminal detection

At startup, `internal/tui/terminal/` detects the terminal emulator via environment variables and exposes its capabilities as a bitfield.

**Detection order** (most-specific first):

| Env var | Terminal |
|---|---|
| `WT_SESSION` | Windows Terminal |
| `KITTY_WINDOW_ID` | Kitty |
| `ALACRITTY_LOG` | Alacritty |
| `WEZTERM_EXECUTABLE` | WezTerm |
| `TILIX_ID` | Tilix |
| `KONSOLE_VERSION` | Konsole |
| `GNOME_TERMINAL_SCREEN` / `VTE_VERSION` | GNOME Terminal |
| `TERM_PROGRAM=vscode` | VS Code |
| `TERM_PROGRAM=iTerm.app` | iTerm2 |
| `TERM_PROGRAM=Apple_Terminal` | Terminal.app |
| `TERM=foot*` | foot |

**Capabilities** (bitfield — used internally by helper functions):

| Capability | Description |
|---|---|
| `CapTruecolor` | 24-bit color |
| `CapHyperlinks` | OSC 8 clickable links |
| `CapItalic` | ANSI italic attribute |
| `CapFaint` | ANSI faint/dim attribute |
| `CapStrikethrough` | ANSI strikethrough |
| `CapWindowTitle` | OSC 0/2 window title |

**Per-terminal capability exceptions:**

- **Terminal.app**: No truecolor, no hyperlinks, no strikethrough (256-color only)
- **Konsole**: No hyperlinks (disabled by default in most versions)
- **Unknown terminals**: Conservative — only `CapTruecolor` if `COLORTERM=truecolor`

**Multiplexer awareness:** When `TMUX` or `STY` (screen) is detected, `Info.Multiplexed` is set to `true`. Detection still identifies the underlying terminal, but callers should be aware capabilities may be degraded through the multiplexer.

**Known limitations:**
- SSH sessions: terminal env vars are not forwarded by default → `Unknown`
- Containers: no terminal env vars → `Unknown` (conservative fallback)
- tmux/screen: env vars may not propagate; detection is best-effort

**Usage:**

```go
// Use capability-aware helpers — they check detection + plain mode internally
link := tui.Hyperlink("https://example.com", "click here")
dim  := tui.Faint("secondary text")
em   := tui.Italic("emphasis")
del  := tui.Strikethrough("removed")
tui.WindowTitle("crust status")
```

## Adding a New TUI Component

1. Create `internal/tui/yourpkg/yourpkg.go` with `//go:build !notui`
2. Create `internal/tui/yourpkg/yourpkg_notui.go` with `//go:build notui`
3. Both files must export the same public API
4. Use `tui.Print*` helpers for output, `tui.Style*` for styling
5. Check `tui.IsPlainMode()` for runtime plain fallback in the TUI build
6. Verify: `go build ./...` and `go build -tags notui ./...`
