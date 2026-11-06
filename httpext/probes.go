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

// ReadyzStatus returns (200, "ok") when checker is non-nil and in a clean
// state, else (503, "not ready").
func ReadyzStatus(checker ReadinessChecker) (int, string) {
	if checker == nil || !checker.IsCleanState() {
		return http.StatusServiceUnavailable, "not ready"
	}
	return http.StatusOK, "ok"
}

// StartupStatus returns (200, "ok") when checker is non-nil and has joined the
// cluster, else (503, "not started").
func StartupStatus(checker ReadinessChecker) (int, string) {
	if checker == nil || !checker.IsStarted() {
		return http.StatusServiceUnavailable, "not started"
	}
	return http.StatusOK, "ok"
}

// LivezStatus always returns (200, "ok").
func LivezStatus() (int, string) {
	return http.StatusOK, "ok"
}

// ReadyzHandler returns 200 when the node is in a clean state, else 503.
func ReadyzHandler(checker ReadinessChecker) http.HandlerFunc {
	return statusHandler(func() (int, string) { return ReadyzStatus(checker) })
}

// StartupHandler returns 200 when the node has joined the cluster, else 503.
func StartupHandler(checker ReadinessChecker) http.HandlerFunc {
	return statusHandler(func() (int, string) { return StartupStatus(checker) })
}

// LivezHandler always returns 200.
func LivezHandler() http.HandlerFunc {
	return statusHandler(LivezStatus)
}

func statusHandler(status func() (int, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		code, body := status()
		if code != http.StatusOK {
			http.Error(w, body, code)
			return
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}
