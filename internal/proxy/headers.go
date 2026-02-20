package proxy

import (
	"net/http"
	"strings"
)

// WarningBlockIndex is a high index value used for injected warning blocks
// to avoid conflicts with actual content block indices.
const WarningBlockIndex = 999

// HopByHopHeaders are headers that should not be forwarded through the proxy.
var HopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Host":                true,
	"Origin":              true,
	"Referer":             true,
}

// copyHeaders copies response headers from src to dst, stripping hop-by-hop
// headers and any additional headers listed in the Connection header value
// per RFC 7230 §6.1.
func copyHeaders(dst, src http.Header) {
	// Build dynamic hop-by-hop set from Connection header
	connHop := make(map[string]bool)
	for _, v := range src["Connection"] {
		for name := range strings.SplitSeq(v, ",") {
			connHop[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}

	for key, values := range src {
		if HopByHopHeaders[key] || connHop[key] {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// stripHopByHopHeaders removes hop-by-hop headers from outbound requests,
// including any additional headers listed in the Connection header value
// per RFC 7230 §6.1.
func stripHopByHopHeaders(h http.Header) {
	// Parse Connection header before deleting it
	for _, v := range h["Connection"] {
		for name := range strings.SplitSeq(v, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for k := range HopByHopHeaders {
		h.Del(k)
	}
}
