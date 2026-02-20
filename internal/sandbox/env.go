package sandbox

import (
	"os"
	"runtime"
	"sync"
)

// ==================== Proxy URL (cooperative routing) ====================

var (
	proxyURLMu sync.RWMutex
	proxyURL   string
)

// SetProxyURL stores the proxy URL for env var injection into sandboxed processes.
// When set, sanitizedEnv() appends ANTHROPIC_BASE_URL and OPENAI_BASE_URL so that
// agents route through the Crust proxy. When empty (default), no vars are injected.
func SetProxyURL(url string) {
	proxyURLMu.Lock()
	proxyURL = url
	proxyURLMu.Unlock()
}

// getProxyURL returns the current proxy URL.
func getProxyURL() string {
	proxyURLMu.RLock()
	defer proxyURLMu.RUnlock()
	return proxyURL
}

// sanitizedEnv returns a minimal, safe environment for the sandboxed process.
// Only allowlisted variables are passed through to prevent leaking secrets
// (API keys, tokens, etc.) into the sandbox.
func sanitizedEnv() []string {
	var env []string
	for _, key := range safeEnvKeys() {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}

	// Inject proxy vars dynamically when the Crust proxy is running.
	// These are non-secret URLs that tell agents to route through the proxy.
	if url := getProxyURL(); url != "" {
		env = append(env, "ANTHROPIC_BASE_URL="+url)
		env = append(env, "OPENAI_BASE_URL="+url+"/v1")
	}

	return env
}

// safeEnvKeys returns the platform-appropriate set of safe environment variable names.
func safeEnvKeys() []string {
	if runtime.GOOS == "windows" {
		return []string{
			"PATH", "USERPROFILE", "USERNAME", "HOMEDRIVE", "HOMEPATH",
			"LANG", "TERM", "TEMP", "TMP", "TZ",
			"SYSTEMROOT", "COMSPEC", "PATHEXT",
		}
	}
	return []string{"PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "SHELL", "TMPDIR", "TZ"}
}
