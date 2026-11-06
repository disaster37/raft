package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	raft "github.com/disaster37/raft"
	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/observ"
	"github.com/disaster37/raft/pki"
	"github.com/disaster37/raft/storage"
	"github.com/disaster37/raft/testutil"
)

func TestSecurityRejectsUntrustedCAPeer(t *testing.T) {
	ca1, _ := pki.NewMintingCA("ca1", "org", 365*24*time.Hour)
	ca2, _ := pki.NewMintingCA("ca2", "org", 365*24*time.Hour)
	serverLeaf := issueLeafFor(t, ca1, "node", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	clientLeaf := issueLeafFor(t, ca2, "client", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	serverProvider := newProvider(serverLeaf, ca1)
	clientProvider := newProvider(clientLeaf, ca2)
	addr, stop := startTLSServer(t, serverProvider)
	defer stop()
	if _, err := tls.Dial("tcp", addr, clientProvider.DialTLSConfig("127.0.0.1")); err == nil {
		t.Fatal("expected untrusted CA rejection")
	}
}

func TestSecurityRejectsWrongSANPeer(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	serverLeaf := issueLeafFor(t, ca, "node", []string{"wrong.example.com"}, nil)
	clientLeaf := issueLeafFor(t, ca, "client", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	serverProvider := newProvider(serverLeaf, ca)
	clientProvider := newProvider(clientLeaf, ca)
	addr, stop := startTLSServer(t, serverProvider)
	defer stop()
	if _, err := tls.Dial("tcp", addr, clientProvider.DialTLSConfig("127.0.0.1")); err == nil {
		t.Fatal("expected wrong SAN rejection")
	}
}

func TestSecurityRejectsExpiredAndFutureCerts(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", 365*24*time.Hour)
	clientLeaf := issueLeafFor(t, ca, "client", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	clientProvider := newProvider(clientLeaf, ca)
	for _, window := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{"expired", time.Now().Add(-2 * time.Hour), time.Now().Add(-time.Hour)},
		{"future", time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour)},
	} {
		t.Run(window.name, func(t *testing.T) {
			serverLeaf := issueCustomLeaf(t, ca, "node", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, window.notBefore, window.notAfter)
			serverProvider := newProvider(serverLeaf, ca)
			addr, stop := startTLSServer(t, serverProvider)
			defer stop()
			if _, err := tls.Dial("tcp", addr, clientProvider.DialTLSConfig("127.0.0.1")); err == nil {
				t.Fatal("expected invalid validity rejection")
			}
		})
	}
}

func TestSecurityFilePermissions(t *testing.T) {
	ln := testutil.FreeListener(t)
	addr := testutil.FreeAddrFromListener(t, ln)
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Dir = dir
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.TLS.Enabled = true
	cfg.TLS.KeyringRotationEnabled = false
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = 100 * time.Millisecond
	n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{CustomListener: ln, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := n.WaitForLeader(ctx); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
	checks := []struct {
		path string
		mode os.FileMode
	}{
		{dir, 0o700},
		{filepath.Join(dir, "snapshots"), 0o700},
		{filepath.Join(dir, "raft.db"), 0o600},
		{filepath.Join(dir, "node-id"), 0o600},
		{filepath.Join(dir, "tls", "node.key"), 0o600},
		{filepath.Join(dir, "tls", "ca.key"), 0o600},
	}
	for _, check := range checks {
		info, err := os.Stat(check.path)
		if err != nil {
			t.Fatalf("stat %s: %v", check.path, err)
		}
		if info.Mode().Perm() != check.mode {
			t.Fatalf("%s mode = %o, want %o", check.path, info.Mode().Perm(), check.mode)
		}
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type failAfterSealer struct {
	inner     storage.Sealer
	mu        sync.Mutex
	calls     int
	failAfter int
}

func (s *failAfterSealer) Seal(plain []byte) (storage.EncryptedValue, error) {
	s.mu.Lock()
	s.calls++
	fail := s.calls > s.failAfter
	s.mu.Unlock()
	if fail {
		return storage.EncryptedValue{}, errors.New("sealer unavailable")
	}
	return s.inner.Seal(plain)
}

func (s *failAfterSealer) SealString(plain string) (string, error) {
	s.mu.Lock()
	s.calls++
	fail := s.calls > s.failAfter
	s.mu.Unlock()
	if fail {
		return "", errors.New("sealer unavailable")
	}
	return s.inner.SealString(plain)
}

func (s *failAfterSealer) Open(ev storage.EncryptedValue) ([]byte, error) {
	return s.inner.Open(ev)
}

func (s *failAfterSealer) OpenString(stored string) (string, error) {
	return s.inner.OpenString(stored)
}

func TestSecurityNoPrivateKeyInLogs(t *testing.T) {
	var buf syncBuffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.DebugLevel)

	keyFile := filepath.Join(t.TempDir(), "keys.json")
	if err := storage.GenerateKeyFile(keyFile); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	rawKeyFile, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Primary string            `json:"primary"`
		Keys    map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(rawKeyFile, &parsed); err != nil {
		t.Fatal(err)
	}
	b64Key := parsed.Keys[parsed.Primary]
	rawKey, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		t.Fatal(err)
	}
	hexKey := hex.EncodeToString(rawKey)
	keeper, err := storage.LoadAESGCMKeeper(keyFile, "raft")
	if err != nil {
		t.Fatal(err)
	}
	sealer := &failAfterSealer{inner: keeper, failAfter: 1}

	const plaintextSecret = "test-plaintext-secret-value"
	ln := testutil.FreeListener(t)
	addr := testutil.FreeAddrFromListener(t, ln)
	cfg := config.DefaultConfig()
	cfg.Dir = t.TempDir()
	cfg.NodeID = "log-node"
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.TLS.Enabled = true
	cfg.TLS.Organization = plaintextSecret
	cfg.TLS.KeyringRotationEnabled = true
	cfg.TLS.RotationPeriod = 100 * time.Millisecond
	cfg.TLS.RotationCheckInterval = 50 * time.Millisecond
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = time.Hour
	n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{
		CustomListener: ln,
		Logger:         observ.NewLogrusAdapter(logger),
		Sealer:         sealer,
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := n.WaitForLeader(ctx); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "keyring rotation failed") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = n.Close()
	out := buf.String()
	if !strings.Contains(out, "keyring rotation failed") {
		t.Fatalf("rotation error path was not exercised: %s", out)
	}
	for _, forbidden := range []string{"PRIVATE KEY", b64Key, hexKey, plaintextSecret} {
		if forbidden == "" {
			continue
		}
		if strings.Contains(out, forbidden) {
			t.Fatalf("logs contain forbidden material %q: %s", forbidden, out)
		}
	}
}

func newProvider(leaf tls.Certificate, ca *pki.MintingCA) *transportProvider {
	return &transportProvider{leaf: leaf, pool: ca.CertPool()}
}

type transportProvider struct {
	leaf tls.Certificate
	pool *x509.CertPool
}

func (p *transportProvider) DialTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.leaf},
		RootCAs:      p.pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}
}

func (p *transportProvider) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.leaf},
		ClientCAs:    p.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
}

func startTLSServer(t *testing.T, provider *transportProvider) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := tls.Server(c, provider.ServerTLSConfig())
				_ = tlsConn.Handshake()
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func issueLeafFor(t *testing.T, ca *pki.MintingCA, cn string, dns []string, ips []net.IP) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := ca.IssuePeerCertificate(cn, "org", dns, ips, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func issueCustomLeaf(t *testing.T, ca *pki.MintingCA, cn string, dns []string, ips []net.IP, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"org"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.CACertificate(), &key.PublicKey, ca.Signer())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
}
