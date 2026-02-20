package rulelist

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
)

// RenderPlain displays rules as plain text (no interactivity).
func RenderPlain(rulesList []rules.Rule, total int) error {
	fmt.Printf("Crust Rules (%d total)\n\n", total)

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

	if len(builtinRules) > 0 {
		fmt.Println("--- Builtin Rules ---")
		fmt.Println()
		for _, r := range builtinRules {
			PrintRule(r, "  ")
			fmt.Println()
		}
	}

	fmt.Println("--- User Rules ---")
	if len(userRulesByFile) == 0 {
		fmt.Println("  (none)")
		fmt.Println("  Add rules with: crust add-rule <file.yaml>")
	} else {
		filenames := make([]string, 0, len(userRulesByFile))
		for f := range userRulesByFile {
			filenames = append(filenames, f)
		}
		sort.Strings(filenames)
		for _, filename := range filenames {
			fmt.Printf("\n  [%s]\n", filename)
			for _, r := range userRulesByFile[filename] {
				PrintRule(r, "    ")
			}
		}
	}
	fmt.Println()
	return nil
}

// PrintRule prints a single rule in plain text format.
func PrintRule(r rules.Rule, prefix string) {
	enabled := r.Enabled == nil || *r.Enabled
	status := "[ON]"
	if !enabled {
		status = "[OFF]"
	}
	fmt.Printf("%s%s %s\n", prefix, status, r.Name)

	desc := r.Description
	if desc == "" {
		desc = r.Message
	}
	if desc != "" {
		fmt.Printf("%s  %s\n", prefix, desc)
	}

	ops := strings.Join(r.GetActions(), ",")
	if ops == "" {
		ops = "all"
	}
	fmt.Printf("%s  [%s]  block %-12s  %d hits\n",
		prefix, string(r.GetSeverity()), ops, r.HitCount)
}
