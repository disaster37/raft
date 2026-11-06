// Package transport provides plaintext and mTLS Raft stream layers with
// per-dial DNS resolution and hot-reloading TLS material.
package transport

import (
	"fmt"
	"net"
	"strconv"
)

// HostAddr implements net.Addr while preserving the DNS hostname so Raft
// peers re-resolve the hostname on each connection instead of pinning a
// resolved IP.
type HostAddr struct {
	Host string
	Port int
}

// NewHostAddr parses addr as host:port without resolving the hostname.
func NewHostAddr(addr string) (net.Addr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse host addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("parse host addr port %q: %w", portStr, err)
	}
	return HostAddr{Host: host, Port: port}, nil
}

// Network implements net.Addr.
func (a HostAddr) Network() string { return "tcp" }

// String implements net.Addr.
func (a HostAddr) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) }
