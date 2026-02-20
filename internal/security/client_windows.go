//go:build windows

package security

import (
	"context"
	"net"
	"net/http"

	"github.com/Microsoft/go-winio"
)

// APITransport returns an HTTP transport that connects via Windows named pipe.
// The HTTP request URL host is ignored; all traffic goes through the pipe.
func APITransport(socketPath string) http.RoundTripper {
	name := pipeName(socketPath)
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return winio.DialPipe(name, nil)
		},
	}
}
