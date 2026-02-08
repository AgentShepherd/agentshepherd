//go:build linux

package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/BakeLens/crust/internal/logger"
)

// Landlock syscall number for version detection
const sysLandlockCreateRuleset = 444

// Landlock flags
const landlockCreateRulesetVersion = 1 << 0

// MinRequiredLandlockABI is the minimum Landlock ABI version.
// v1 (5.13+): filesystem only, v2 (5.19+): +refer, v3 (6.2+): +truncate+network,
// v4 (6.7+): +TCP bind/connect.
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

// checkLandlockVersion checks Landlock version on first use.
// Panics if the kernel is too old (below MinRequiredLandlockABI).
func checkLandlockVersion() error {
	if landlockChecked {
		return nil
	}
	landlockChecked = true

	version := detectLandlockABI()
	if version == 0 {
		panic("Landlock not available. Requires Linux 5.13+ with CONFIG_SECURITY_LANDLOCK=y")
	}
	if version < MinRequiredLandlockABI {
		panic(fmt.Sprintf("Landlock v%d detected but v%d+ required (kernel 6.2+). Upgrade your kernel to use the sandbox.", version, MinRequiredLandlockABI))
	}
	landlockLog.Info("Landlock v%d detected", version)
	return nil
}

// helperBinaryName is the sandbox helper binary name.
var helperBinaryName = "bakelens-sandbox"

// helperExecPaths lists possible system locations for the sandbox helper.
// Only absolute, system-installed paths are allowed — CWD paths are excluded
// because agents can substitute a fake binary in the working directory.
var helperExecPaths = []string{
	"/usr/libexec/crust/bakelens-sandbox",
	"/usr/local/libexec/crust/bakelens-sandbox",
}

// findBakelensSandbox locates the bakelens-sandbox binary.
// Search order: user-local → system paths → relative to binary.
func findBakelensSandbox() (string, error) {
	// Check user-local paths first (~/.local/libexec/crust/bakelens-sandbox)
	if home, err := os.UserHomeDir(); err == nil {
		userPath := filepath.Join(home, ".local", "libexec", "crust", helperBinaryName)
		if verifyCurrentUserOwnership(userPath) {
			return userPath, nil
		}
	}

	// Fallback: check standard system paths
	for _, path := range helperExecPaths {
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink == 0 {
			return path, nil
		}
	}

	// Fallback: check relative to executable, but verify ownership
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates := []string{
			filepath.Join(dir, helperBinaryName),
			filepath.Join(dir, "..", "libexec", "crust", helperBinaryName),
		}
		for _, path := range candidates {
			if verifyHelperOwnership(path) || verifyCurrentUserOwnership(path) {
				return path, nil
			}
		}
	}

	return "", fmt.Errorf("bakelens-sandbox not found; install to ~/.local/libexec/crust/")
}

// verifyHelperOwnership checks that the helper binary exists and is owned by root
// to prevent an agent from substituting a malicious binary in a user-writable directory.
func verifyHelperOwnership(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	// Reject symlinks to prevent TOCTOU attacks
	if fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if stat.Uid != 0 {
		return false
	}
	if fi.Mode()&0002 != 0 {
		return false
	}
	return true
}

// verifyCurrentUserOwnership checks that the helper binary exists, is owned by
// the current user, and is not world-writable.
func verifyCurrentUserOwnership(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	// Reject symlinks to prevent TOCTOU attacks
	if fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid := os.Getuid()
	if uid < 0 || stat.Uid != uint32(uid) { //nolint:gosec // uid is non-negative on Linux
		return false
	}
	if fi.Mode()&0002 != 0 {
		return false
	}
	return true
}

// unifiedPolicyJSON is the JSON structure for the unified bakelens-sandbox binary.
// Must match the Rust Policy struct in policy.rs.
type unifiedPolicyJSON struct {
	Version  int              `json:"version"`
	Landlock *landlockSection `json:"landlock,omitempty"`
	Seccomp  *seccompSection  `json:"seccomp,omitempty"`
	Command  []string         `json:"command"`
}

type landlockSection struct {
	ABI          int             `json:"abi"`
	AllowPaths   []pathEntryJSON `json:"allow_paths"`
	Strict       bool            `json:"strict"`
	AllowPartial bool            `json:"allow_partial"`
}

type pathEntryJSON struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type seccompSection struct {
	DenySyscalls []string `json:"deny_syscalls"`
}

// defaultDenySyscalls is the default set of syscalls to block.
var defaultDenySyscalls = []string{
	"ptrace", "process_vm_readv", "process_vm_writev",
	"mount", "umount2", "pivot_root",
	"move_mount", "fsopen", "fsmount", "fsconfig", "fspick", "open_tree",
	"init_module", "delete_module", "finit_module",
	"kexec_load", "kexec_file_load",
	"perf_event_open", "bpf", "userfaultfd",
	"keyctl", "add_key", "request_key",
	"unshare", "setns",
	"io_uring_setup", "io_uring_enter", "io_uring_register",
	"memfd_create",
	"clone3", "pidfd_getfd", "open_by_handle_at",
	"name_to_handle_at", "process_madvise", "syslog",
}

// buildUnifiedPolicy builds the JSON policy for the unified bakelens-sandbox binary.
func buildUnifiedPolicy(command []string) ([]byte, error) {
	var pathModes []PathMode
	if len(currentRules) > 0 {
		pathModes = IntentAwareAllowPaths(currentRules)
	} else {
		pathModes = defaultPathModes()
	}

	abi := detectLandlockABI()
	entries := make([]pathEntryJSON, 0, len(pathModes))
	for _, pm := range pathModes {
		mode := string(pm.Mode)
		if mode == "0" {
			mode = "none"
		}
		entries = append(entries, pathEntryJSON{Path: pm.Path, Mode: mode})
	}

	policy := unifiedPolicyJSON{
		Version: 1,
		Landlock: &landlockSection{
			ABI:          abi,
			AllowPaths:   entries,
			Strict:       true,
			AllowPartial: true,
		},
		Seccomp: &seccompSection{
			DenySyscalls: defaultDenySyscalls,
		},
		Command: command,
	}

	return json.Marshal(policy)
}

// execute runs a command inside the sandbox by spawning bakelens-sandbox.
// Each invocation spawns a fresh process — no persistent state.
func (s *Sandbox) execute(command []string) (int, error) {
	if err := checkLandlockVersion(); err != nil {
		return 0, err
	}

	helperPath, err := findBakelensSandbox()
	if err != nil {
		return 0, err
	}

	policyJSON, err := buildUnifiedPolicy(command)
	if err != nil {
		return 0, fmt.Errorf("build policy: %w", err)
	}

	cmd := exec.Command(helperPath) //nolint:gosec // trusted path from findBakelensSandbox
	cmd.Stdin = bytes.NewReader(policyJSON)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = sanitizedEnv()

	err = cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 1, fmt.Errorf("bakelens-sandbox failed: %w", err)
	}
	return 0, nil
}
