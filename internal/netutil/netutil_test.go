package netutil

import (
	"errors"
	"syscall"
	"testing"
)

func TestIsConnRefused(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"syscall", syscall.ECONNREFUSED, true},
		{"wrapped", errors.Join(errors.New("dial"), syscall.ECONNREFUSED), true},
		{"string", errors.New("dial tcp: connection refused"), true},
		{"other", errors.New("timeout"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsConnRefused(tt.err); got != tt.want {
				t.Fatalf("IsConnRefused(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestSplitHostPortDefault(t *testing.T) {
	tests := []struct {
		addr     string
		defPort  int
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"", 8081, "", 8081, false},
		{"127.0.0.1:9000", 8081, "127.0.0.1", 9000, false},
		{"localhost", 8081, "localhost", 8081, false},
		{"127.0.0.1:bad", 8081, "", 0, true},
		{"[::1]:9000", 8081, "::1", 9000, false},
	}
	for _, tt := range tests {
		host, port, err := SplitHostPortDefault(tt.addr, tt.defPort)
		if (err != nil) != tt.wantErr {
			t.Fatalf("SplitHostPortDefault(%q) err = %v, wantErr %v", tt.addr, err, tt.wantErr)
		}
		if err != nil {
			continue
		}
		if host != tt.wantHost || port != tt.wantPort {
			t.Fatalf("SplitHostPortDefault(%q) = (%q,%d), want (%q,%d)", tt.addr, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

func TestDeriveBindHost(t *testing.T) {
	tests := []struct {
		addr string
		port int
		want string
	}{
		{"", 8081, "127.0.0.1:8081"},
		{"0.0.0.0:9000", 8081, "127.0.0.1:9000"},
		{"[::]:9000", 8081, "127.0.0.1:9000"},
		{"10.0.0.1:9000", 8081, "10.0.0.1:9000"},
		{"bad", 8081, "127.0.0.1:8081"},
	}
	for _, tt := range tests {
		if got := DeriveBindHost(tt.addr, tt.port); got != tt.want {
			t.Fatalf("DeriveBindHost(%q,%d) = %q, want %q", tt.addr, tt.port, got, tt.want)
		}
	}
}
