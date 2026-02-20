package sandbox

// SecurityRule is the interface that sandbox uses to access rule properties.
// This decouples the sandbox package from internal/rules, allowing extraction.
// Implemented by rules.Rule (via getter methods) and testRule (in tests).
type SecurityRule interface {
	IsEnabled() bool
	GetName() string
	GetBlockPaths() []string
	GetBlockExcept() []string
	GetActions() []string
	GetBlockHosts() []string // for network IP deny-list
}

// Operation represents the type of operation.
// Mirrors rules.Operation but defined here to avoid importing rules.
// OpNetwork is used by the rules engine (Layer 0/1) for matching but is
// not a valid sandbox operation — filterOps strips it before Layer 2.
type Operation string

const (
	OpRead    Operation = "read"
	OpWrite   Operation = "write"
	OpDelete  Operation = "delete"
	OpCopy    Operation = "copy"
	OpMove    Operation = "move"
	OpExecute Operation = "execute"
	OpNetwork Operation = "network"
)
