package sandbox

import "os"

// DefaultAllowPaths returns the default paths that sandboxed commands can access.
// These are the minimum paths needed for most commands to work.
//
// NOTE: /proc is intentionally excluded to block access to /proc/<pid>/cmdline
// and /proc/<pid>/environ which may contain API keys passed as arguments or
// environment variables. Commands like ps/top won't work, but AI agents rarely
// need them. This is a security-first decision.
func DefaultAllowPaths() []string {
	paths := []string{
		"/bin",   // Basic binaries
		"/usr",   // User binaries, libraries, includes
		"/lib",   // Shared libraries
		"/lib64", // 64-bit shared libraries
		"/tmp",   // Temporary files
		"/var",   // Variable data (logs, spool, etc.)
		"/dev",   // Device files (null, zero, urandom, etc.)
		"/etc",   // Configuration files
		"/sys",   // Sysfs (hardware info)
		"/run",   // Runtime variable data
		"/opt",   // Optional packages
		"/sbin",  // System binaries
		// NOTE: /proc is NOT included - see function comment
	}

	// Add home directory if available
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, home)
	}

	// Add current working directory if available
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		paths = append(paths, cwd)
	}

	return paths
}

// MinimalAllowPaths returns a minimal set of paths for highly restricted execution.
// Use this when you want maximum security and only need basic command execution.
func MinimalAllowPaths() []string {
	return []string{
		"/bin",
		"/usr/bin",
		"/lib",
		"/lib64",
		"/tmp",
		"/dev",
	}
}

// AllowPathsWithProc returns the default paths plus /proc access.
// Use this only when commands genuinely need /proc (e.g., debugging tools).
// WARNING: This allows reading /proc/*/cmdline and /proc/*/environ which
// may expose API keys. Only use when Layer 1 rules block sensitive paths.
func AllowPathsWithProc() []string {
	paths := DefaultAllowPaths()
	return append(paths, "/proc")
}
