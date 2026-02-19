//go:build unix

package security

import (
	"context"
	"net"
	"net/http"
)

// APITransport returns an HTTP transport that connects via Unix domain socket.
// The HTTP request URL host is ignored; all traffic goes through the socket.
func APITransport(socketPath string) http.RoundTripper {
	dialer := &net.Dialer{}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
}
