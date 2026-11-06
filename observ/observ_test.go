package observ

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

type captureLogger struct {
	lines []string
}

func (c *captureLogger) Debug(string, map[string]any) {}
func (c *captureLogger) Info(msg string, _ map[string]any) {
	c.lines = append(c.lines, msg)
}
func (c *captureLogger) Warn(string, map[string]any)         {}
func (c *captureLogger) Error(string, error, map[string]any) {}

func TestHclogWriterLineBuffering(t *testing.T) {
	capture := &captureLogger{}
	w := NewHclogWriter(capture)
	if _, err := w.Write([]byte("partial")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(capture.lines) != 0 {
		t.Fatalf("expected no flushed lines, got %v", capture.lines)
	}
	if _, err := w.Write([]byte(" line\r\nsecond\n\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(capture.lines) != 2 {
		t.Fatalf("lines = %v, want 2", capture.lines)
	}
	if capture.lines[0] != "partial line" || capture.lines[1] != "second" {
		t.Fatalf("lines = %v", capture.lines)
	}
}

func TestLogrusAdapterAndNoop(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	l.SetLevel(logrus.DebugLevel)
	adapter := NewLogrusAdapter(l)
	adapter.Debug("debug", map[string]any{"k": "v"})
	adapter.Info("info", nil)
	adapter.Warn("warn", nil)
	adapter.Error("error", io.EOF, nil)
	out := buf.String()
	for _, want := range []string{"debug", "info", "warn", "error"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q missing %q", out, want)
		}
	}
	noop := NewNoopLogger()
	noop.Debug("x", nil)
	noop.Info("x", nil)
	noop.Warn("x", nil)
	noop.Error("x", nil, nil)
	if NewLogrusAdapter(nil) == nil {
		t.Fatal("nil logrus adapter should return noop")
	}
}

func TestPrometheusMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)
	m.UpdateFromRaftStats(map[string]string{
		"state":          "Leader",
		"term":           "3",
		"last_log_index": "10",
		"commit_index":   "9",
		"applied_index":  "9",
		"fsm_pending":    "0",
		"num_peers":      "2",
	})
	m.IncLeaderChanges()
	m.ObserveFollowerHeartbeat("n1", 12)
	m.ObserveAppliedIndexDelta("n1", 1)
	m.IncJoinAttempts()
	m.IncJoinFailures()
	m.IncDNSResolutionFailures()
	m.IncDialRetries()
	m.IncLeadershipTransfers()
	m.IncDeadServersDetected()
	m.SetKeyringTerm(2)
	m.SetKeyringActiveKeyAgeSeconds(5)
	m.IncKeyringRotations("staged")

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(families) == 0 {
		t.Fatal("expected metric families")
	}
	// A second registration on the same registry must not panic.
	_ = NewPrometheusMetrics(reg)
	noop := NewNoopMetrics()
	noop.UpdateFromRaftStats(nil)
	noop.IncLeaderChanges()
	noop.ObserveFollowerHeartbeat("", 0)
	noop.ObserveAppliedIndexDelta("", 0)
	noop.IncJoinAttempts()
	noop.IncJoinFailures()
	noop.IncDNSResolutionFailures()
	noop.IncDialRetries()
	noop.IncLeadershipTransfers()
	noop.IncDeadServersDetected()
	noop.SetKeyringTerm(0)
	noop.SetKeyringActiveKeyAgeSeconds(0)
	noop.IncKeyringRotations("")
}
