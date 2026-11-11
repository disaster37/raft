package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/raft/pki"
)

func TestHostAddrPreservesHostname(t *testing.T) {
	addr, err := NewHostAddr("example.com:8081")
	if err != nil {
		t.Fatalf("NewHostAddr: %v", err)
	}
	if addr.Network() != "tcp" || addr.String() != "example.com:8081" {
		t.Fatalf("addr = %s/%s", addr.Network(), addr.String())
	}
	if _, err := NewHostAddr("bad"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := NewHostAddr("host:bad"); err == nil {
		t.Fatal("expected port error")
	}
}

func TestPlainStreamLayer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	layer := newPlainStreamLayerFromListener(ln, nil)
	defer layer.Close()
	go func() {
		conn, err := layer.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(buf)
	}()
	conn, err := layer.Dial(hraft.ServerAddress(layer.Addr().String()), time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
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
	layer.CloseIdleConnections()
}

func TestTLSStreamLayerMTLS(t *testing.T) {
	ca, err := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueLeaf(t, ca, "node")
	pool := ca.CertPool()
	provider := NewDynamicTLSProvider(leaf, pool, pool, true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	layer := newTLSStreamLayerFromListener(ln, nil, provider)
	defer layer.Close()
	go func() {
		conn, err := layer.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(buf)
	}()
	conn, err := layer.Dial(hraft.ServerAddress(layer.Addr().String()), time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "y" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestDynamicTLSProviderHotReloadLeafAndCA(t *testing.T) {
	ca1, err := pki.NewMintingCA("ca1", "org", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := pki.NewMintingCA("ca2", "org", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf1 := issueLeaf(t, ca1, "node")
	leaf2 := issueLeaf(t, ca2, "node")
	provider := NewDynamicTLSProvider(leaf1, ca1.CertPool(), ca1.CertPool(), true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	layer := newTLSStreamLayerFromListener(ln, nil, provider)
	defer layer.Close()
	go func() {
		for {
			conn, err := layer.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				_, _ = c.Write(buf)
			}(conn)
		}
	}()
	addr := hraft.ServerAddress(layer.Addr().String())
	conn, err := layer.Dial(addr, time.Second)
	if err != nil {
		t.Fatalf("initial dial: %v", err)
	}
	_ = conn.Close()

	provider.Update(leaf2, ca2.CertPool(), ca2.CertPool())
	conn, err = layer.Dial(addr, time.Second)
	if err != nil {
		t.Fatalf("dial after CA reload: %v", err)
	}
	_ = conn.Close()

	// A client that still trusts only CA1 must be rejected.
	oldProvider := NewDynamicTLSProvider(leaf1, ca1.CertPool(), ca1.CertPool(), true)
	dialer := &net.Dialer{Timeout: time.Second}
	if _, err := tls.DialWithDialer(dialer, "tcp", string(addr), oldProvider.DialTLSConfig("127.0.0.1")); err == nil {
		t.Fatal("expected old CA to be rejected")
	}
}

func TestFileWatcherRejectsInvalidAndKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _, err := ca.EncodePEM()
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "node.crt")
	keyFile := filepath.Join(dir, "node.key")
	caFile := filepath.Join(dir, "ca.crt")
	for path, data := range map[string][]byte{certFile: certPEM, keyFile: keyPEM, caFile: caPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	watcher, err := NewFileWatcher(certFile, keyFile, caFile, time.Millisecond, time.Hour, true, nil)
	if err != nil {
		t.Fatalf("NewFileWatcher: %v", err)
	}
	if watcher.Provider() == nil {
		t.Fatal("missing provider")
	}
	if err := os.WriteFile(certFile, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := watcher.Reload(); err == nil {
		t.Fatal("expected reload error")
	}
	if watcher.Provider().CurrentCertPool() == nil {
		t.Fatal("previous state was lost")
	}
	if _, err := NewFileWatcher("missing", "missing", "missing", time.Millisecond, time.Hour, true, nil); err == nil {
		t.Fatal("expected initial load error")
	}
}

func TestRetryingStreamLayerRetriesOnConnRefused(t *testing.T) {
	ca, err := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)

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
		layer := newTLSStreamLayerFromListener(server, nil, provider)
		defer layer.Close()
		conn, err := layer.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(buf)
	}()

	inner := newTLSStreamLayerFromListener(&dummyListener{}, nil, provider)
	retrying := NewRetryingStreamLayer(inner, provider, time.Second, 10, 50*time.Millisecond, nil)
	conn, err := retrying.Dial(hraft.ServerAddress(addr), time.Second)
	if err != nil {
		t.Fatalf("retrying dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "z" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestRetryingStreamLayerNoRetryOnTLSFailure(t *testing.T) {
	ca1, _ := pki.NewMintingCA("ca1", "org", 365*24*time.Hour)
	ca2, _ := pki.NewMintingCA("ca2", "org", 365*24*time.Hour)
	leaf1 := issueLeaf(t, ca1, "node")
	leaf2 := issueLeaf(t, ca2, "node")
	serverProvider := NewDynamicTLSProvider(leaf1, ca1.CertPool(), ca1.CertPool(), true)
	clientProvider := NewDynamicTLSProvider(leaf2, ca2.CertPool(), ca2.CertPool(), true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	layer := newTLSStreamLayerFromListener(ln, nil, serverProvider)
	defer layer.Close()
	go func() {
		conn, err := layer.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	inner := newTLSStreamLayerFromListener(&dummyListener{}, nil, clientProvider)
	retrying := NewRetryingStreamLayer(inner, clientProvider, time.Second, 3, 10*time.Millisecond, nil)
	if _, err := retrying.Dial(hraft.ServerAddress(layer.Addr().String()), time.Second); err == nil {
		t.Fatal("expected TLS failure")
	}
}

func TestResolveAdvertiseAddr(t *testing.T) {
	addr, err := ResolveAdvertiseAddr("127.0.0.1:8081", time.Second, nil)
	if err != nil || addr.Port != 8081 {
		t.Fatalf("addr = %v err=%v", addr, err)
	}
	if _, err := ResolveAdvertiseAddr("invalid.invalid:8081", 10*time.Millisecond, nil); err == nil {
		t.Fatal("expected resolution error")
	}
}

func issueLeaf(t *testing.T, ca *pki.MintingCA, cn string) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := ca.IssuePeerCertificate(cn, "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	if parsed, err := x509.ParseCertificate(leaf.Certificate[0]); err == nil {
		leaf.Leaf = parsed
	}
	return leaf
}

type dummyListener struct{}

func (d *dummyListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (d *dummyListener) Close() error              { return nil }
func (d *dummyListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1} }

func TestNewPlainAndTLSStreamLayers(t *testing.T) {
	plain, err := NewPlainStreamLayer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("NewPlainStreamLayer: %v", err)
	}
	if plain.Addr() == nil {
		t.Fatal("plain addr nil")
	}
	_ = plain.Close()

	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	tlsLayer, err := NewTLSStreamLayer("127.0.0.1:0", nil, provider)
	if err != nil {
		t.Fatalf("NewTLSStreamLayer: %v", err)
	}
	if tlsLayer.Addr() == nil {
		t.Fatal("tls addr nil")
	}
	_ = tlsLayer.Close()
}

func TestDynamicTLSProviderMethods(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	if provider.CurrentCertPool() == nil {
		t.Fatal("nil pool")
	}
	if _, err := provider.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"}); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if _, err := provider.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown"}); err != nil {
		t.Fatalf("GetCertificate unknown: %v", err)
	}
	if _, err := provider.GetClientCertificate(&tls.CertificateRequestInfo{}); err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if _, err := provider.GetClientCertificate(&tls.CertificateRequestInfo{AcceptableCAs: [][]byte{[]byte("x")}}); err != nil {
		t.Fatalf("GetClientCertificate acceptable: %v", err)
	}
	if _, err := provider.GetConfigForClient(&tls.ClientHelloInfo{}); err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	if provider.ServerTLSConfig() == nil {
		t.Fatal("nil server config")
	}
	if provider.DialTLSConfig("localhost") == nil {
		t.Fatal("nil dial config")
	}
	provider.UpdateKeyringView(leaf, []tls.Certificate{leaf}, ca.CertPool())
	provider.Update(leaf, ca.CertPool(), ca.CertPool())
	empty := &DynamicTLSProvider{}
	if _, err := empty.GetCertificate(nil); err == nil {
		t.Fatal("expected no certificate error")
	}
	if _, err := empty.GetClientCertificate(nil); err == nil {
		t.Fatal("expected no certificate error")
	}
	if _, err := empty.GetConfigForClient(nil); err == nil {
		t.Fatal("expected no state error")
	}
	if empty.CurrentCertPool() != nil {
		t.Fatal("expected nil pool")
	}
}

func TestFileWatcherStart(t *testing.T) {
	dir := t.TempDir()
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	certPEM, keyPEM, _ := ca.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	caPEM, _, _ := ca.EncodePEM()
	certFile := filepath.Join(dir, "node.crt")
	keyFile := filepath.Join(dir, "node.key")
	caFile := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(certFile, certPEM, 0o600)
	_ = os.WriteFile(keyFile, keyPEM, 0o600)
	_ = os.WriteFile(caFile, caPEM, 0o600)
	watcher, err := NewFileWatcher(certFile, keyFile, caFile, time.Millisecond, time.Hour, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watcher.Start(ctx)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done
}

func TestMuxListenerAndPrefixConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handled := make(chan struct{}, 1)
	mux := &muxListener{listener: ln, handler: func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(conn, buf)
		handled <- struct{}{}
	}}
	defer mux.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		for {
			conn, err := mux.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	go func() {
		conn, err := net.Dial("tcp", mux.Addr().String())
		if err != nil {
			return
		}
		_, _ = conn.Write(EchoMagic)
		_ = conn.Close()
	}()
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("echo handler not invoked")
	}
	go func() {
		conn, err := net.Dial("tcp", mux.Addr().String())
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("DATA"))
		_ = conn.Close()
	}()
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("data connection not accepted")
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "DATA" {
		t.Fatalf("prefix = %q", buf)
	}
	_ = conn.Close()
}

func TestMuxListenerEchoConcurrencyLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	mux := &muxListener{
		listener: ln,
		handler: func(conn net.Conn) {
			defer conn.Close()
			started <- struct{}{}
			<-release
		},
		sem:         make(chan struct{}, 1),
		peekTimeout: time.Second,
	}
	defer mux.Close()
	go func() {
		for {
			if _, err := mux.Accept(); err != nil {
				return
			}
		}
	}()

	first, err := net.Dial("tcp", mux.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write(EchoMagic); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first echo handler did not start")
	}

	second, err := net.Dial("tcp", mux.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.Write(EchoMagic); err != nil {
		t.Fatal(err)
	}
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := second.Read(buf); err == nil {
		t.Fatal("expected excess echo connection to be closed")
	}
	select {
	case <-started:
		t.Fatal("second echo handler started despite limit")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
}

func TestMuxListenerPeekDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := &muxListener{
		listener:    ln,
		handler:     func(net.Conn) {},
		sem:         make(chan struct{}, 1),
		peekTimeout: 50 * time.Millisecond,
	}
	defer mux.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		for {
			conn, err := mux.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	stalled, err := net.Dial("tcp", mux.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	time.Sleep(100 * time.Millisecond)
	_ = stalled.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := stalled.Read(buf); err == nil {
		t.Fatal("expected stalled connection to be closed")
	}

	valid, err := net.Dial("tcp", mux.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()
	if _, err := valid.Write([]byte("DATA")); err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-accepted:
		defer conn.Close()
		got := make([]byte, 4)
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != "DATA" {
			t.Fatalf("prefix = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("valid connection not accepted after stalled peek")
	}
}

func TestNewStreamTransportPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr, closer, advertise, err := NewStreamTransport(TransportOptions{
		BindAddr:       ln.Addr().String(),
		AdvertiseAddr:  ln.Addr().String(),
		CustomListener: ln,
		MaxPool:        1,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("NewStreamTransport: %v", err)
	}
	if tr == nil || closer == nil || advertise == "" {
		t.Fatal("missing transport components")
	}
	_ = closer.Close()
}

func TestNewStreamTransportTLS(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr, closer, advertise, err := NewStreamTransport(TransportOptions{
		BindAddr:       ln.Addr().String(),
		AdvertiseAddr:  ln.Addr().String(),
		CustomListener: ln,
		TLSProvider:    provider,
		MaxPool:        1,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("NewStreamTransport TLS: %v", err)
	}
	if tr == nil || closer == nil || advertise == "" {
		t.Fatal("missing transport components")
	}
	_ = closer.Close()
}

func TestStreamLayerDelegationAndErrors(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	inner := newTLSStreamLayerFromListener(&dummyListener{}, nil, provider)
	retrying := NewRetryingStreamLayer(inner, nil, time.Second, 0, time.Millisecond, nil)
	if retrying.Addr() == nil {
		t.Fatal("nil addr")
	}
	if _, err := retrying.Dial("bad", time.Second); err == nil {
		t.Fatal("expected dial error")
	}
	_ = retrying.Close()

	plain := newPlainStreamLayerFromListener(&dummyListener{}, nil)
	if _, err := plain.Dial("bad", time.Millisecond); err == nil {
		t.Fatal("expected plain dial error")
	}
	_ = plain.Close()

	tlsLayer := newTLSStreamLayerFromListener(&dummyListener{}, nil, provider)
	if _, err := tlsLayer.Dial("bad", time.Millisecond); err == nil {
		t.Fatal("expected tls dial error")
	}
	_ = tlsLayer.Close()
}

func TestNewStreamTransportErrors(t *testing.T) {
	if _, _, _, err := NewStreamTransport(TransportOptions{AdvertiseAddr: "invalid.invalid:1", AdvertiseResolveTimeout: 10 * time.Millisecond}); err == nil {
		t.Fatal("expected advertise error")
	}
	if _, _, _, err := NewStreamTransport(TransportOptions{BindAddr: "bad", AdvertiseAddr: "127.0.0.1:1"}); err == nil {
		t.Fatal("expected listen error")
	}
}

func TestResolveAdvertiseAddrLogs(t *testing.T) {
	var buf bytes.Buffer
	if _, err := ResolveAdvertiseAddr("invalid.invalid:1", 10*time.Millisecond, &buf); err == nil {
		t.Fatal("expected error")
	}
	if buf.Len() == 0 {
		t.Fatal("expected retry log")
	}
}

func TestDynamicTLSProviderClientCertMatch(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	if _, err := provider.GetClientCertificate(&tls.CertificateRequestInfo{AcceptableCAs: [][]byte{parsed.RawIssuer}}); err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	provider.UpdateKeyringView(leaf, nil, ca.CertPool())
	if provider.CurrentCertPool() == nil {
		t.Fatal("nil pool")
	}
}

func TestPrefixConnPartialRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	conn := &prefixConn{Conn: server, prefix: []byte("ab")}
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); err != nil || n != 1 || string(buf) != "a" {
		t.Fatalf("read = %d %q %v", n, buf, err)
	}
	if n, err := conn.Read(buf); err != nil || n != 1 || string(buf) != "b" {
		t.Fatalf("read = %d %q %v", n, buf, err)
	}
}

func TestStreamLayerListenErrors(t *testing.T) {
	if _, err := NewPlainStreamLayer("bad", nil); err == nil {
		t.Fatal("expected plain listen error")
	}
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	if _, err := NewTLSStreamLayer("bad", nil, provider); err == nil {
		t.Fatal("expected tls listen error")
	}
}

func TestRetryingStreamLayerResolveError(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	inner := newTLSStreamLayerFromListener(&dummyListener{}, nil, provider)
	retrying := NewRetryingStreamLayer(inner, provider, time.Millisecond, 0, time.Millisecond, nil)
	if _, err := retrying.Dial("invalid.invalid:1", time.Millisecond); err == nil {
		t.Fatal("expected resolve error")
	}
}

func TestRetryingStreamLayerDefaults(t *testing.T) {
	inner := newPlainStreamLayerFromListener(&dummyListener{}, nil)
	retrying := NewRetryingStreamLayer(inner, nil, 0, -1, 0, nil)
	if retrying.Addr() == nil {
		t.Fatal("nil addr")
	}
}

func TestFileWatcherExpiredAndFuture(t *testing.T) {
	dir := t.TempDir()
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	caPEM, _, _ := ca.EncodePEM()
	caFile := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(caFile, caPEM, 0o600)
	for _, window := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{"expired", time.Now().Add(-2 * time.Hour), time.Now().Add(-time.Hour)},
		{"future", time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour)},
	} {
		t.Run(window.name, func(t *testing.T) {
			certPEM, keyPEM := issueCustomCert(t, ca, window.notBefore, window.notAfter)
			certFile := filepath.Join(dir, fmt.Sprintf("%s.crt", window.name))
			keyFile := filepath.Join(dir, fmt.Sprintf("%s.key", window.name))
			_ = os.WriteFile(certFile, certPEM, 0o600)
			_ = os.WriteFile(keyFile, keyPEM, 0o600)
			if _, err := NewFileWatcher(certFile, keyFile, caFile, time.Millisecond, time.Hour, true, nil); err == nil {
				t.Fatal("expected invalid cert error")
			}
		})
	}
}

func TestPrefixConnEmptyPrefix(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	conn := &prefixConn{Conn: server}
	go func() { _, _ = client.Write([]byte("x")) }()
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); err != nil || n != 1 || string(buf) != "x" {
		t.Fatalf("read = %d %q %v", n, buf, err)
	}
}

func issueCustomCert(t *testing.T, ca *pki.MintingCA, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "node"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.CACertificate(), &key.PublicKey, ca.Signer())
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func TestTrackedConnEvictsOnClose(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	plain := newPlainStreamLayerFromListener(&dummyListener{}, nil)
	tlsLayer := newTLSStreamLayerFromListener(&dummyListener{}, nil, provider)
	retrying := NewRetryingStreamLayer(plain, nil, time.Second, 0, time.Millisecond, nil).(*RetryingStreamLayer)

	tests := []struct {
		name  string
		track func(net.Conn) net.Conn
		count func() int
	}{
		{"plain", plain.track, func() int {
			plain.mu.Lock()
			defer plain.mu.Unlock()
			return len(plain.conns)
		}},
		{"tls", tlsLayer.track, func() int {
			tlsLayer.mu.Lock()
			defer tlsLayer.mu.Unlock()
			return len(tlsLayer.conns)
		}},
		{"retrying", retrying.track, func() int {
			retrying.mu.Lock()
			defer retrying.mu.Unlock()
			return len(retrying.conns)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer func() { _ = client.Close() }()
			tracked := tt.track(server)
			if got := tt.count(); got != 1 {
				t.Fatalf("tracked connections = %d, want 1", got)
			}
			if err := tracked.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			if got := tt.count(); got != 0 {
				t.Fatalf("tracked connections after close = %d, want 0", got)
			}
		})
	}
}

func TestCloseIdleConnectionsNoDeadlock(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	leaf := issueLeaf(t, ca, "node")
	provider := NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	plain := newPlainStreamLayerFromListener(&dummyListener{}, nil)
	tlsLayer := newTLSStreamLayerFromListener(&dummyListener{}, nil, provider)
	retrying := NewRetryingStreamLayer(plain, nil, time.Second, 0, time.Millisecond, nil).(*RetryingStreamLayer)

	tests := []struct {
		name      string
		track     func(net.Conn) net.Conn
		closeIdle func()
		count     func() int
	}{
		{"plain", plain.track, plain.CloseIdleConnections, func() int {
			plain.mu.Lock()
			defer plain.mu.Unlock()
			return len(plain.conns)
		}},
		{"tls", tlsLayer.track, tlsLayer.CloseIdleConnections, func() int {
			tlsLayer.mu.Lock()
			defer tlsLayer.mu.Unlock()
			return len(tlsLayer.conns)
		}},
		{"retrying", retrying.track, retrying.CloseIdleConnections, func() int {
			retrying.mu.Lock()
			defer retrying.mu.Unlock()
			return len(retrying.conns)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer func() { _ = client.Close() }()
			_ = tt.track(server)
			done := make(chan struct{})
			go func() {
				tt.closeIdle()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("CloseIdleConnections deadlocked")
			}
			if got := tt.count(); got != 0 {
				t.Fatalf("tracked connections after close = %d, want 0", got)
			}
		})
	}
}

func TestRetryingStreamLayerPlaintextRetry(t *testing.T) {
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
		layer := newPlainStreamLayerFromListener(server, nil)
		defer layer.Close()
		conn, err := layer.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(buf)
	}()

	inner := newPlainStreamLayerFromListener(&dummyListener{}, nil)
	retrying := NewRetryingStreamLayer(inner, nil, time.Second, 10, 50*time.Millisecond, nil)
	conn, err := retrying.Dial(hraft.ServerAddress(addr), time.Second)
	if err != nil {
		t.Fatalf("plaintext retrying dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("p")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "p" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestRetryingStreamLayerCloseIdleCascadesToInner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inner := newPlainStreamLayerFromListener(ln, nil)
	retrying := NewRetryingStreamLayer(inner, nil, time.Second, 0, time.Millisecond, nil).(*RetryingStreamLayer)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := inner.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	conn, err := retrying.Dial(hraft.ServerAddress(ln.Addr().String()), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("inner accept did not complete")
	}
	defer func() { _ = serverConn.Close() }()

	retrying.mu.Lock()
	outbound := len(retrying.conns)
	retrying.mu.Unlock()
	inner.mu.Lock()
	inbound := len(inner.conns)
	inner.mu.Unlock()
	if outbound != 1 || inbound != 1 {
		t.Fatalf("tracked outbound=%d inbound=%d, want 1/1", outbound, inbound)
	}

	retrying.CloseIdleConnections()

	retrying.mu.Lock()
	outbound = len(retrying.conns)
	retrying.mu.Unlock()
	inner.mu.Lock()
	inbound = len(inner.conns)
	inner.mu.Unlock()
	if outbound != 0 || inbound != 0 {
		t.Fatalf("after cascade outbound=%d inbound=%d, want 0/0", outbound, inbound)
	}
}
