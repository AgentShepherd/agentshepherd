//go:build !linux

package sandbox

// SetRules is a no-op on non-Linux platforms.
// Landlock mode derivation is only available on Linux.
func SetRules(_ []SecurityRule) {}
