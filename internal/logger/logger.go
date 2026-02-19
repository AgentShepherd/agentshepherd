package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Level represents log level
type Level int

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
)

var (
	globalLevel   = LevelInfo
	globalColored = true
	globalMu      sync.RWMutex
)

var (
	styleTrace = lipgloss.NewStyle().Foreground(lipgloss.Color("#E8C872")) // warm gold
	styleDebug = lipgloss.NewStyle().Foreground(lipgloss.Color("#F0C674")) // gold
	styleInfo  = lipgloss.NewStyle().Foreground(lipgloss.Color("#A8B545")) // warm sage
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD93D")) // bright gold
	styleError = lipgloss.NewStyle().Foreground(lipgloss.Color("#E05A3A")) // warm terracotta
	styleFaint = lipgloss.NewStyle().Faint(true)
)

// Logger provides leveled logging
type Logger struct {
	prefix string
}

// New creates a new logger with the given prefix
func New(prefix string) *Logger {
	return &Logger{prefix: prefix}
}

// SetGlobalLevel sets the global log level
func SetGlobalLevel(level Level) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLevel = level
}

// ParseLevel converts a string to a Level, returning an error if unrecognized.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return LevelDebug, nil
	case "info", "":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (valid: trace, debug, info, warn, error)", s)
}

// SetGlobalLevelFromString sets log level from string
func SetGlobalLevelFromString(level string) {
	if l, err := ParseLevel(level); err == nil {
		SetGlobalLevel(l)
	}
}

// SetColored enables or disables colored output
func SetColored(colored bool) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalColored = colored
}

func (l *Logger) log(level Level, levelStr string, style lipgloss.Style, format string, args ...any) {
	globalMu.RLock()
	if level < globalLevel {
		globalMu.RUnlock()
		return
	}
	colored := globalColored
	globalMu.RUnlock()

	timestamp := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)

	if colored {
		label := style.Render("[" + levelStr + "]")
		fmt.Fprintf(os.Stderr, "%s %s %s %s\n",
			styleFaint.Render(timestamp), label, styleFaint.Render("["+l.prefix+"]"), msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s [%s] [%s] %s\n",
			timestamp, levelStr, l.prefix, msg)
	}
}

// Trace logs a trace message (most verbose)
func (l *Logger) Trace(format string, args ...any) {
	l.log(LevelTrace, "TRACE", styleTrace, format, args...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...any) {
	l.log(LevelDebug, "DEBUG", styleDebug, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...any) {
	l.log(LevelInfo, "INFO", styleInfo, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...any) {
	l.log(LevelWarn, "WARN", styleWarn, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...any) {
	l.log(LevelError, "ERROR", styleError, format, args...)
}
