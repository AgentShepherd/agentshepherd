package proxy

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
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Host":                true,
	"Origin":              true,
	"Referer":             true,
}
