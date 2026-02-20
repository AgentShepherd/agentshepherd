//go:build notui

package rulelist

import (
	"github.com/BakeLens/crust/internal/rules"
)

// Render displays rules as plain text (no interactivity in notui build).
func Render(rulesList []rules.Rule, total int) error {
	return RenderPlain(rulesList, total)
}
