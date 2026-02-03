//go:build linux

package sandbox

import (
	"fmt"
	"syscall"

	"github.com/AgentShepherd/agentshepherd/internal/logger"
)

// Landlock syscall number for version detection
const sysLandlockCreateRuleset = 444

// Landlock flags
const landlockCreateRulesetVersion = 1 << 0

// MinRequiredLandlockABI is the minimum Landlock ABI version required by AgentShepherd.
// Version 3 (kernel 6.6+) is required for network restriction support.
const MinRequiredLandlockABI = 3

var landlockLog = logger.New("landlock")
var landlockChecked bool

// detectLandlockABI detects the Landlock ABI version supported by the kernel.
func detectLandlockABI() int {
	ret, _, err := syscall.Syscall(
		sysLandlockCreateRuleset,
		0, // attr = NULL
		0, // size = 0
		landlockCreateRulesetVersion,
	)
	if err != 0 {
		return 0 // Landlock not supported
	}
	return int(ret)
}

// isLandlockSupported returns true if Landlock is available on this kernel.
func isLandlockSupported() bool {
	return detectLandlockABI() >= 1
}

// persistentSandbox holds the long-running sandbox helper.
var persistentSandbox *PersistentSandbox

// checkLandlockVersion checks and logs Landlock version on first use.
func checkLandlockVersion() error {
	if landlockChecked {
		return nil
	}
	landlockChecked = true

	version := detectLandlockABI()
	if version == 0 {
		return fmt.Errorf("Landlock not available. Requires Linux 5.13+ with CONFIG_SECURITY_LANDLOCK=y")
	}
	if version < MinRequiredLandlockABI {
		return fmt.Errorf("Landlock v%d required (kernel 6.6+), detected v%d", MinRequiredLandlockABI, version)
	}
	landlockLog.Info("Landlock v%d detected (required: v%d+)", version, MinRequiredLandlockABI)
	return nil
}

// initPersistentSandbox initializes the persistent sandbox helper.
func initPersistentSandbox() error {
	if persistentSandbox != nil {
		return nil
	}

	if err := checkLandlockVersion(); err != nil {
		return err
	}

	ps, err := NewPersistentSandbox(DefaultAllowPaths())
	if err != nil {
		return fmt.Errorf("failed to create persistent sandbox: %w", err)
	}

	persistentSandbox = ps
	return nil
}

// execute runs the command using the persistent sandbox helper.
// This ensures the parent process (AgentShepherd) remains unrestricted.
func (s *Sandbox) execute(profilePath string, command []string) (int, error) {
	_ = profilePath // Not used in persistent mode

	// Initialize persistent sandbox on first use (includes version check)
	if err := initPersistentSandbox(); err != nil {
		return 0, err
	}

	return persistentSandbox.Exec(command)
}
