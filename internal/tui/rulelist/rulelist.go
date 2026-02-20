//go:build !notui

package rulelist

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"io"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/tui"
)

// ruleItem implements list.Item for a single rule.
type ruleItem struct {
	rule rules.Rule
}

func (i ruleItem) FilterValue() string { return i.rule.Name }

// Title returns plain text — styling is done in the custom delegate to avoid
// ANSI escape corruption when bubbles/list applies filter highlighting.
func (i ruleItem) Title() string {
	return i.rule.Name
}

func (i ruleItem) Description() string {
	r := i.rule
	sev := r.GetSeverity()

	// Operations
	ops := strings.Join(r.GetActions(), ",")
	if ops == "" {
		ops = "all"
	}

	// Targets
	var targets []string
	targets = append(targets, r.Block.Paths...)
	for _, h := range r.Block.Hosts {
		targets = append(targets, "host:"+h)
	}
	if r.Match != nil {
		if r.Match.Path != "" {
			targets = append(targets, r.Match.Path)
		}
		if r.Match.Command != "" {
			targets = append(targets, "cmd:"+r.Match.Command)
		}
		if r.Match.Host != "" {
			targets = append(targets, "host:"+r.Match.Host)
		}
	}

	targetStr := ""
	if len(targets) > 0 {
		targetStr = targets[0]
		if len(targets) > 1 {
			targetStr = fmt.Sprintf("%s (+%d)", targets[0], len(targets)-1)
		}
		if len(targetStr) > 35 {
			targetStr = targetStr[:32] + "..."
		}
	}

	return fmt.Sprintf("%s  %s %-12s  %s  %s",
		tui.SeverityBadge(string(sev)),
		tui.StyleMuted.Render(tui.IconBlock), ops,
		tui.StyleMuted.Render(targetStr),
		tui.StyleMuted.Render(tui.IconBolt+" "+strconv.FormatInt(r.HitCount, 10)+" hits"))
}

// headerItem is a non-selectable separator for group headers.
type headerItem struct {
	title string
}

func (h headerItem) FilterValue() string { return "" }
func (h headerItem) Title() string       { return tui.Separator(h.title) }
func (h headerItem) Description() string { return "" }

// ruleDelegate renders rule items with proper styling that won't leak
// ANSI escapes into the filter highlight overlay.
type ruleDelegate struct {
	styles list.DefaultItemStyles
}

func newRuleDelegate() ruleDelegate {
	styles := list.NewDefaultItemStyles()
	styles.SelectedTitle = styles.SelectedTitle.
		Foreground(tui.ColorAccent).
		BorderLeftForeground(tui.ColorAccent)
	styles.SelectedDesc = styles.SelectedDesc.
		Foreground(tui.ColorMuted).
		BorderLeftForeground(tui.ColorAccent)
	return ruleDelegate{styles: styles}
}

func (d ruleDelegate) Height() int                         { return 2 }
func (d ruleDelegate) Spacing() int                        { return 1 }
func (d ruleDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }
func (d ruleDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	ri, ok := item.(ruleItem)
	if !ok {
		// headerItem — render as separator
		if h, ok := item.(headerItem); ok {
			fmt.Fprint(w, tui.Separator(h.title))
		}
		return
	}

	selected := index == m.Index()
	enabled := ri.rule.Enabled == nil || *ri.rule.Enabled

	// Build styled title
	var icon string
	var name string
	if enabled {
		icon = tui.StyleSuccess.Render(tui.IconCheck)
		name = tui.StyleBold.Render(ri.rule.Name)
	} else {
		icon = tui.StyleMuted.Render(tui.IconCircle)
		name = tui.Strikethrough(ri.rule.Name)
	}
	title := icon + " " + name
	desc := ri.Description()

	if selected {
		title = d.styles.SelectedTitle.Render("> " + ri.rule.Name)
		desc = d.styles.SelectedDesc.Render("  " + desc)
	} else {
		title = "  " + title
		desc = "  " + desc
	}

	fmt.Fprintf(w, "%s\n%s", title, desc)
}

// model is the bubbletea model for the interactive rule list.
type model struct {
	list   list.Model
	width  int
	height int
}

// Render displays rules in an interactive list.
// Supports scroll navigation, filtering by name.
// Falls back to static display in plain mode.
func Render(rulesList []rules.Rule, total int) error {
	if tui.IsPlainMode() {
		return RenderPlain(rulesList, total)
	}

	items := buildListItems(rulesList)

	// Use custom delegate to avoid ANSI escape leak in filter mode
	delegate := newRuleDelegate()

	l := list.New(items, delegate, 80, 24)
	l.Title = fmt.Sprintf("Crust Rules (%d total)", total)
	l.Styles.Title = tui.StyleTitle
	l.Styles.FilterPrompt = lipgloss.NewStyle().Foreground(tui.ColorAccent)
	l.Styles.FilterCursor = lipgloss.NewStyle().Foreground(tui.ColorSuccess)
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)

	m := model{list: l}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(msg.Width, msg.Height)

	case tea.KeyMsg:
		if msg.String() == "q" && !m.list.SettingFilter() {
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) View() string {
	return m.list.View()
}

// buildListItems converts rules into list items grouped by source.
func buildListItems(rulesList []rules.Rule) []list.Item {
	var items []list.Item

	// Group by source
	var builtinRules []rules.Rule
	userRulesByFile := make(map[string][]rules.Rule)
	for _, r := range rulesList {
		if r.Source == rules.SourceBuiltin {
			builtinRules = append(builtinRules, r)
		} else {
			filename := filepath.Base(r.FilePath)
			if filename == "" || filename == "." {
				filename = "(unknown)"
			}
			userRulesByFile[filename] = append(userRulesByFile[filename], r)
		}
	}

	// Builtin rules
	if len(builtinRules) > 0 {
		for _, r := range builtinRules {
			items = append(items, ruleItem{rule: r})
		}
	}

	// User rules by file
	if len(userRulesByFile) > 0 {
		filenames := make([]string, 0, len(userRulesByFile))
		for f := range userRulesByFile {
			filenames = append(filenames, f)
		}
		sort.Strings(filenames)

		for _, filename := range filenames {
			fileRules := userRulesByFile[filename]
			// Add file header as a divider
			items = append(items, headerItem{title: filename})
			for _, r := range fileRules {
				items = append(items, ruleItem{rule: r})
			}
		}
	}

	return items
}
