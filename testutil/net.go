// Package testutil provides helpers for tests that need real listeners and
// deterministic clocks.
package testutil

import (
	"net"
	"testing"
)

// FreeListener reserves a loopback TCP listener and closes it during test
// cleanup. Tests must pass the listener to the server instead of probing a
// port and closing it, which races with other tests.
func FreeListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// FreeAddrFromListener returns the host:port of ln.
func FreeAddrFromListener(t *testing.T, ln net.Listener) string {
	t.Helper()
	if ln == nil {
		t.Fatal("nil listener")
	}
	return ln.Addr().String()
}
