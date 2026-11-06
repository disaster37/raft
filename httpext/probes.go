// Package httpext provides HTTP probes and leader-forwarding middleware.
package httpext

import "net/http"

// ReadinessChecker reports whether the node is started and in a clean state.
type ReadinessChecker interface {
	IsCleanState() bool
	IsStarted() bool
}

// LeaderInfo reports leadership and the current leader address.
type LeaderInfo interface {
	IsLeader() bool
	LeaderAddress() string
}

// ReadyzHandler returns 200 when the node is in a clean state, else 503.
func ReadyzHandler(checker ReadinessChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if checker == nil || !checker.IsCleanState() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

// StartupHandler returns 200 when the node has joined the cluster, else 503.
func StartupHandler(checker ReadinessChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if checker == nil || !checker.IsStarted() {
			http.Error(w, "not started", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

// LivezHandler always returns 200.
func LivezHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}
