package integration

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/raft/pki"
	"github.com/disaster37/raft/transport"
)

func TestRetryingStreamLayerSurvivesPortBounce(t *testing.T) {
	ca, err := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	provider := transport.NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	go func() {
		time.Sleep(200 * time.Millisecond)
		server, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		tlsListener := tls.NewListener(server, provider.ServerTLSConfig())
		defer tlsListener.Close()
		conn, err := tlsListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(buf)
	}()

	inner, err := transport.NewTLSStreamLayer("127.0.0.1:0", nil, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	retrying := transport.NewRetryingStreamLayer(inner, provider, time.Second, 10, 50*time.Millisecond, nil)
	conn, err := retrying.Dial(hraft.ServerAddress(addr), time.Second)
	if err != nil {
		t.Fatalf("retrying dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "x" {
		t.Fatalf("echo = %q", buf)
	}
}
