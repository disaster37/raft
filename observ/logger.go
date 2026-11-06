// Package observ provides logging and metrics adapters used across the raft
// packages.
package observ

import (
	"bytes"
	"io"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// Logger is the structured logging interface used by the library. Implementations
// must be safe for concurrent use.
type Logger interface {
	Debug(msg string, fields map[string]any)
	Info(msg string, fields map[string]any)
	Warn(msg string, fields map[string]any)
	Error(msg string, err error, fields map[string]any)
}

// LogrusAdapter adapts a logrus.Logger to Logger.
type LogrusAdapter struct {
	logger *logrus.Logger
}

// NewLogrusAdapter returns a Logger backed by l. A nil logger yields a no-op
// logger.
func NewLogrusAdapter(l *logrus.Logger) Logger {
	if l == nil {
		return NewNoopLogger()
	}
	return &LogrusAdapter{logger: l}
}

func (a *LogrusAdapter) Debug(msg string, fields map[string]any) {
	a.logger.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (a *LogrusAdapter) Info(msg string, fields map[string]any) {
	a.logger.WithFields(logrus.Fields(fields)).Info(msg)
}

func (a *LogrusAdapter) Warn(msg string, fields map[string]any) {
	a.logger.WithFields(logrus.Fields(fields)).Warn(msg)
}

func (a *LogrusAdapter) Error(msg string, err error, fields map[string]any) {
	entry := a.logger.WithFields(logrus.Fields(fields))
	if err != nil {
		entry = entry.WithError(err)
	}
	entry.Error(msg)
}

// NoopLogger discards every log entry.
type NoopLogger struct{}

// NewNoopLogger returns a Logger that discards all output.
func NewNoopLogger() Logger { return NoopLogger{} }

func (NoopLogger) Debug(string, map[string]any)        {}
func (NoopLogger) Info(string, map[string]any)         {}
func (NoopLogger) Warn(string, map[string]any)         {}
func (NoopLogger) Error(string, error, map[string]any) {}

// HclogWriter is a thread-safe, line-buffered io.Writer that forwards complete
// lines to a Logger. Raft and hclog may split a single log line across
// multiple Write calls, so a line is only flushed once a newline arrives.
type HclogWriter struct {
	logger Logger
	mu     sync.Mutex
	buf    []byte
}

// NewHclogWriter returns an io.Writer that logs complete lines through l.
func NewHclogWriter(l Logger) io.Writer {
	if l == nil {
		l = NewNoopLogger()
	}
	return &HclogWriter{logger: l}
}

// Write implements io.Writer.
func (w *HclogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf = append(w.buf, p...)
	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}
		line := bytes.TrimSuffix(w.buf[:idx], []byte("\r"))
		w.flushLine(line)
		w.buf = w.buf[idx+1:]
	}
	return len(p), nil
}

func (w *HclogWriter) flushLine(line []byte) {
	msg := strings.TrimSpace(string(line))
	if msg == "" {
		return
	}
	w.logger.Info(msg, map[string]any{"component": "raft"})
}
