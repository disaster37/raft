package httpext

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/disaster37/raft/pki"
	"github.com/disaster37/raft/transport"
)

type fakeReadiness struct {
	clean   bool
	started bool
}

func (f fakeReadiness) IsCleanState() bool { return f.clean }
func (f fakeReadiness) IsStarted() bool    { return f.started }

type fakeLeader struct {
	leader bool
	addr   string
}

func (f fakeLeader) IsLeader() bool        { return f.leader }
func (f fakeLeader) LeaderAddress() string { return f.addr }

func TestProbesReadyzAndStartup(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		checker ReadinessChecker
		want    int
	}{
		{"ready", ReadyzHandler(fakeReadiness{clean: true}), fakeReadiness{clean: true}, http.StatusOK},
		{"not ready", ReadyzHandler(fakeReadiness{}), fakeReadiness{}, http.StatusServiceUnavailable},
		{"nil ready", ReadyzHandler(nil), nil, http.StatusServiceUnavailable},
		{"started", StartupHandler(fakeReadiness{started: true}), fakeReadiness{started: true}, http.StatusOK},
		{"not started", StartupHandler(fakeReadiness{}), fakeReadiness{}, http.StatusServiceUnavailable},
		{"nil started", StartupHandler(nil), nil, http.StatusServiceUnavailable},
		{"live", LivezHandler(), nil, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != tt.want {
				t.Fatalf("code = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

type countingListener struct {
	net.Listener
	count atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.count.Add(1)
	}
	return conn, err
}

type mutableLeader struct {
	mu   sync.RWMutex
	addr string
}

func (m *mutableLeader) IsLeader() bool { return false }

func (m *mutableLeader) LeaderAddress() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.addr
}

func (m *mutableLeader) set(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addr = addr
}

func newTLSLeader(t *testing.T, ca *pki.MintingCA) (*httptest.Server, tls.Certificate) {
	t.Helper()
	certPEM, keyPEM, err := ca.IssuePeerCertificate("leader", "test-org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("leader"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	return server, leaf
}

func TestLeaderForwardTransportPoolsConnections(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("leader"))
	}))
	counter := &countingListener{Listener: server.Listener}
	server.Listener = counter
	server.StartTLS()
	defer server.Close()

	leaf := server.TLS.Certificates[0]
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	provider := transport.NewDynamicTLSProvider(leaf, pool, pool, false)

	_, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	cfg := LeaderForwardConfig{
		LeaderInfo:            fakeLeader{addr: server.Listener.Addr().String()},
		TargetPort:            port,
		Scheme:                "https",
		TLSProvider:           provider,
		ResponseHeaderTimeout: time.Second,
	}
	handler := LeaderForwardMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/write", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "leader" {
			t.Fatalf("request %d: code=%d body=%q", i, rec.Code, rec.Body.String())
		}
	}
	if got := counter.count.Load(); got != 1 {
		t.Fatalf("accepted connections = %d, want 1 (transport not pooled)", got)
	}
}

func TestLeaderForwardUsesDynamicTLSConfigPerDial(t *testing.T) {
	ca1, err := pki.NewMintingCA("ca1", "org", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := pki.NewMintingCA("ca2", "org", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server1, leaf1 := newTLSLeader(t, ca1)
	defer server1.Close()
	server2, leaf2 := newTLSLeader(t, ca2)
	defer server2.Close()

	provider := transport.NewDynamicTLSProvider(leaf1, ca1.CertPool(), ca1.CertPool(), false)
	leader := &mutableLeader{addr: server1.Listener.Addr().String()}
	cfg := LeaderForwardConfig{
		LeaderInfo:            leader,
		Scheme:                "https",
		TLSProvider:           provider,
		ResponseHeaderTimeout: time.Second,
	}
	handler := LeaderForwardMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/write", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "leader" {
		t.Fatalf("first request: code=%d body=%q", rec.Code, rec.Body.String())
	}

	provider.Update(leaf2, ca2.CertPool(), ca2.CertPool())
	leader.set(server2.Listener.Addr().String())
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/write", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "leader" {
		t.Fatalf("second request after CA rotation: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestLeaderForwardFollowerProxiesToLeader(t *testing.T) {
	var gotMarker string
	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMarker = r.Header.Get("X-Raft-Leader-Forwarded")
		_, _ = w.Write([]byte("leader"))
	}))
	defer leader.Close()
	host, portStr, _ := net.SplitHostPort(leader.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	cfg := LeaderForwardConfig{
		LeaderInfo: fakeLeader{leader: false, addr: leader.Listener.Addr().String()},
		TargetPort: port,
		Scheme:     "http",
	}
	handler := LeaderForwardMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local"))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/write", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "leader" {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	if gotMarker != "1" {
		t.Fatalf("marker = %q", gotMarker)
	}
	_ = host
}

func TestLeaderForwardLoopPreventionHeader(t *testing.T) {
	cfg := LeaderForwardConfig{
		LeaderInfo: fakeLeader{leader: false, addr: "127.0.0.1:1"},
		Scheme:     "http",
	}
	handler := LeaderForwardMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local"))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Raft-Leader-Forwarded", "1")
	handler.ServeHTTP(rec, req)
	if rec.Body.String() != "local" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestLeaderForwardNoLeaderReturns503(t *testing.T) {
	cfg := LeaderForwardConfig{LeaderInfo: fakeLeader{leader: false, addr: ""}, Scheme: "http"}
	handler := LeaderForwardMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local"))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestLeaderForwardGETAndPinnedRoutes(t *testing.T) {
	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("leader"))
	}))
	defer leader.Close()
	_, portStr, _ := net.SplitHostPort(leader.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	cfg := LeaderForwardConfig{
		LeaderInfo:    fakeLeader{leader: false, addr: leader.Listener.Addr().String()},
		TargetPort:    port,
		Scheme:        "http",
		PinnedRouteFn: func(method, path string) bool { return method == http.MethodGet && path == "/pinned" },
	}
	handler := LeaderForwardMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local"))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/other", nil))
	if rec.Body.String() != "local" {
		t.Fatalf("GET should be local, got %q", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pinned", nil))
	if rec.Body.String() != "leader" {
		t.Fatalf("pinned GET should forward, got %q", rec.Body.String())
	}
}

func TestLeaderForwardLeaderServesLocally(t *testing.T) {
	cfg := LeaderForwardConfig{LeaderInfo: fakeLeader{leader: true, addr: "127.0.0.1:1"}, Scheme: "http"}
	handler := LeaderForwardMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local"))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Body.String() != "local" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestStripForwardMarker(t *testing.T) {
	handler := StripForwardMarker("X-Test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "" {
			t.Fatal("header not stripped")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Test", "1")
	handler.ServeHTTP(rec, req)
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestLeaderForwardInvalidLeaderAddress(t *testing.T) {
	cfg := LeaderForwardConfig{LeaderInfo: fakeLeader{addr: "bad"}, Scheme: "http"}
	handler := LeaderForwardMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local"))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestLeaderForwardProxyError(t *testing.T) {
	cfg := LeaderForwardConfig{LeaderInfo: fakeLeader{addr: "127.0.0.1:1"}, Scheme: "http"}
	handler := LeaderForwardMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local"))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestLeaderForwardNilLeaderInfo(t *testing.T) {
	handler := LeaderForwardMiddleware(LeaderForwardConfig{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local"))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Body.String() != "local" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestStripForwardMarkerDefault(t *testing.T) {
	handler := StripForwardMarker("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Raft-Leader-Forwarded") != "" {
			t.Fatal("header not stripped")
		}
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Raft-Leader-Forwarded", "1")
	handler.ServeHTTP(rec, req)
}
