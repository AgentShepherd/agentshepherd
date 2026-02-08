package sandbox

import "os"

// sanitizedEnv returns a minimal, safe environment for the sandboxed process.
// Only allowlisted variables are passed through to prevent leaking secrets
// (API keys, tokens, etc.) into the sandbox.
func sanitizedEnv() []string {
	safe := []string{"PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "SHELL", "TMPDIR", "TZ"}
	var env []string
	for _, key := range safe {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}
	return env
}
