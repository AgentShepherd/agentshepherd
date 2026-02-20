//go:build notui

package dashboard

import (
	"fmt"
	"net/http"
)

// Run prints static status once (no interactivity in notui build).
func Run(mgmtClient *http.Client, proxyBaseURL string, pid int, logFile string) error {
	data := FetchStatus(mgmtClient, proxyBaseURL, pid, logFile)
	fmt.Println(RenderStatic(data))
	return nil
}

// RenderStatic renders a plain text status display.
func RenderStatic(data StatusData) string {
	return RenderPlain(data)
}
