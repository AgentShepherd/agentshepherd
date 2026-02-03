package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
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

// SetGlobalLevelFromString sets log level from string
func SetGlobalLevelFromString(level string) {
	switch strings.ToLower(level) {
	case "trace":
		SetGlobalLevel(LevelTrace)
	case "debug":
		SetGlobalLevel(LevelDebug)
	case "info":
		SetGlobalLevel(LevelInfo)
	case "warn", "warning":
		SetGlobalLevel(LevelWarn)
	case "error":
		SetGlobalLevel(LevelError)
	}
}

// SetColored enables or disables colored output
func SetColored(colored bool) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalColored = colored
}

func (l *Logger) log(level Level, levelStr, color string, format string, args ...interface{}) {
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
		fmt.Fprintf(os.Stderr, "%s %s[%s]%s [%s] %s\n",
			timestamp, color, levelStr, "\033[0m", l.prefix, msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s [%s] [%s] %s\n",
			timestamp, levelStr, l.prefix, msg)
	}
}

// Trace logs a trace message (most verbose)
func (l *Logger) Trace(format string, args ...interface{}) {
	l.log(LevelTrace, "TRACE", "\033[35m", format, args...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, "DEBUG", "\033[36m", format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, "INFO", "\033[32m", format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, "WARN", "\033[33m", format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, "ERROR", "\033[31m", format, args...)
}
