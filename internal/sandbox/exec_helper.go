package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

// execute runs a command inside the sandbox by spawning bakelens-sandbox.
// Each invocation spawns a fresh process — no persistent state.
func (s *Sandbox) execute(command []string) (int, error) {
	policyJSON, err := buildPolicy(command)
	if err != nil {
		return 0, fmt.Errorf("build policy: %w", err)
	}

	return s.RunHelper(policyJSON)
}

// RunHelper spawns bakelens-sandbox, pipes policyJSON on stdin, and returns the exit code.
// On exit code 125 (sandbox setup error), parses the JSON error from stderr
// and returns a *Error with the structured error code.
func (s *Sandbox) RunHelper(policyJSON []byte) (int, error) {
	helperPath, err := findBakelensSandbox()
	if err != nil {
		return 0, err
	}

	cmd := exec.CommandContext(context.Background(), helperPath) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Stdin = bytes.NewReader(policyJSON)
	cmd.Stdout = os.Stdout
	cmd.Env = sanitizedEnv()

	// Tee stderr to both the terminal and a ring buffer so we can parse
	// the structured JSON error on the last line when exit code is 125.
	stderrTee := &lastLineWriter{dest: os.Stderr}
	cmd.Stderr = stderrTee

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start sandbox: %w", err)
	}

	err = cmd.Wait()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if code == ExitSandboxError {
			if se := parseSandboxError(stderrTee.LastLine()); se != nil {
				return code, se
			}
		}
		return code, nil
	}
	if err != nil {
		return 1, fmt.Errorf("bakelens-sandbox failed: %w", err)
	}
	return 0, nil
}

// lastLineWriter writes all data to dest while tracking the last complete line.
// Used to capture bakelens-sandbox's JSON error from the final line of stderr
// without buffering all output.
type lastLineWriter struct {
	dest     *os.File
	mu       sync.Mutex
	lastLine []byte
	partial  []byte // incomplete line (no trailing newline yet)
}

func (w *lastLineWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := w.dest.Write(p)
	if n == 0 {
		return n, err
	}

	w.mu.Lock()
	// Append to partial buffer and extract lines
	w.partial = append(w.partial, p[:n]...)
	for {
		idx := bytes.IndexByte(w.partial, '\n')
		if idx < 0 {
			break
		}
		w.lastLine = make([]byte, idx)
		copy(w.lastLine, w.partial[:idx])
		w.partial = w.partial[idx+1:]
	}
	w.mu.Unlock()

	return n, err
}

// LastLine returns the last complete line written, or the remaining partial if no newline was seen.
func (w *lastLineWriter) LastLine() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	// If there's leftover partial data (no trailing newline), that's the last line
	if len(w.partial) > 0 {
		return w.partial
	}
	return w.lastLine
}
