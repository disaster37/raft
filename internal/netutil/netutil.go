// Package netutil contains small networking helpers shared by the raft
// packages.
package netutil

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// IsConnRefused reports whether err indicates that the remote host actively
// refused the TCP connection (ECONNREFUSED).
func IsConnRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

// SplitHostPortDefault splits addr into host and port. When addr has no port,
// defaultPort is used. An empty or wildcard host is returned unchanged.
func SplitHostPortDefault(addr string, defaultPort int) (host string, port int, err error) {
	if addr == "" {
		return "", defaultPort, nil
	}
	h, p, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		if strings.Contains(splitErr.Error(), "missing port in address") {
			return addr, defaultPort, nil
		}
		return "", 0, fmt.Errorf("split host port %q: %w", addr, splitErr)
	}
	parsed, convErr := strconv.Atoi(p)
	if convErr != nil {
		return "", 0, fmt.Errorf("parse port %q: %w", p, convErr)
	}
	return h, parsed, nil
}

// DeriveBindHost returns a concrete host:port from bindAddr, defaulting
// 0.0.0.0/::/empty to 127.0.0.1 and a missing port to defaultPort.
func DeriveBindHost(bindAddr string, defaultPort int) string {
	host, portStr, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(defaultPort))
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, portStr)
}
