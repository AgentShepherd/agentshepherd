package rules

import "strings"

// hasProcPath checks if any normalized path accesses /proc.
// On Linux, /proc exposes process environ, cmdline, memory, and file
// descriptors — all of which may contain API keys and secrets.
// On non-Linux platforms, /proc paths never appear so this is a no-op.
// This is hardcoded in Go (not YAML) so it cannot be tampered with.
func hasProcPath(paths []string) (bool, string) {
	for _, p := range paths {
		if strings.HasPrefix(p, "/proc/") {
			return true, p
		}
	}
	return false, ""
}
