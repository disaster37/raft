package httpext

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/disaster37/go-raft/pki"
	"github.com/disaster37/go-raft/transport"
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

func TestProbeStatusHelpers(t *testing.T) {
	tests := []struct {
		name string
		call func() (int, string)
		code int
		body string
	}{
		{"ready", func() (int, string) { return ReadyzStatus(fakeReadiness{clean: true}) }, http.StatusOK, "ok"},
		{"not ready", func() (int, string) { return ReadyzStatus(fakeReadiness{}) }, http.StatusServiceUnavailable, "not ready"},
		{"nil ready", func() (int, string) { return ReadyzStatus(nil) }, http.StatusServiceUnavailable, "not ready"},
		{"started", func() (int, string) { return StartupStatus(fakeReadiness{started: true}) }, http.StatusOK, "ok"},
		{"not started", func() (int, string) { return StartupStatus(fakeReadiness{}) }, http.StatusServiceUnavailable, "not started"},
		{"nil started", func() (int, string) { return StartupStatus(nil) }, http.StatusServiceUnavailable, "not started"},
		{"live", LivezStatus, http.StatusOK, "ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := tt.call()
			if code != tt.code || body != tt.body {
				t.Fatalf("status = %d %q, want %d %q", code, body, tt.code, tt.body)
			}
		})
	}
}

func TestForwarderFrameworkAgnostic(t *testing.T) {
	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Forwarded") != "1" {
			t.Errorf("missing loop-prevention header")
		}
		if r.Header.Get("X-Remove") != "" {
			t.Errorf("Connection token header was not stripped")
		}
		if r.Header.Get("Keep-Alive") != "" {
			t.Errorf("hop-by-hop header was not stripped")
		}
		if r.Header.Get("X-Keep") != "yes" {
			t.Errorf("end-to-end header was stripped")
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Leader", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(append([]byte("leader:"), body...))
	}))
	defer leader.Close()
	_, portStr, _ := net.SplitHostPort(leader.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	cfg := LeaderForwardConfig{
		LeaderInfo: fakeLeader{addr: leader.Listener.Addr().String()},
		TargetPort: port,
		Scheme:     "http",
		HeaderName: "X-Test-Forwarded",
	}
	fwd := NewForwarder(cfg)
	if fwd.Client() == nil || fwd.HeaderName() != "X-Test-Forwarded" || fwd.Scheme() != "http" {
		t.Fatalf("forwarder accessors = %v %q %q", fwd.Client(), fwd.HeaderName(), fwd.Scheme())
	}
	if !fwd.ShouldForward(http.MethodPost, "/write", "") {
		t.Fatal("POST should forward")
	}
	if fwd.ShouldForward(http.MethodGet, "/read", "") {
		t.Fatal("GET should not forward")
	}
	if fwd.ShouldForward(http.MethodPost, "/write", "1") {
		t.Fatal("loop header should prevent forwarding")
	}
	if NewForwarder(LeaderForwardConfig{}).ShouldForward(http.MethodPost, "/write", "") {
		t.Fatal("nil leader should not forward")
	}
	if NewForwarder(LeaderForwardConfig{LeaderInfo: fakeLeader{leader: true}}).ShouldForward(http.MethodPost, "/write", "") {
		t.Fatal("leader should not forward")
	}
	pinned := NewForwarder(LeaderForwardConfig{
		LeaderInfo:    fakeLeader{},
		PinnedRouteFn: func(method, path string) bool { return method == http.MethodGet && path == "/pinned" },
	})
	if !pinned.ShouldForward(http.MethodGet, "/pinned", "") {
		t.Fatal("pinned GET should forward")
	}

	if _, _, err := NewForwarder(LeaderForwardConfig{}).Target(); !errors.Is(err, ErrNoLeader) {
		t.Fatalf("no leader err = %v", err)
	}
	if _, _, err := NewForwarder(LeaderForwardConfig{LeaderInfo: fakeLeader{addr: "bad"}}).Target(); !errors.Is(err, ErrInvalidLeaderAddr) {
		t.Fatalf("invalid leader err = %v", err)
	}
	scheme, hostPort, err := fwd.Target()
	if err != nil || scheme != "http" || hostPort != leader.Listener.Addr().String() {
		t.Fatalf("target = %q %q err=%v", scheme, hostPort, err)
	}
	targetURL, err := fwd.TargetURL("/api/v1/traces?x=1")
	if err != nil || targetURL != fmt.Sprintf("http://%s/api/v1/traces?x=1", leader.Listener.Addr().String()) {
		t.Fatalf("target url = %q err=%v", targetURL, err)
	}

	header := http.Header{}
	header.Set("Connection", "X-Remove")
	header.Set("X-Remove", "1")
	header.Set("Keep-Alive", "timeout=5")
	header.Set("X-Keep", "yes")
	resp, err := fwd.Forward(context.Background(), &ForwardRequest{
		Method:     http.MethodPost,
		RequestURI: "/api/v1/traces?x=1",
		Header:     header,
		Body:       strings.NewReader("payload"),
	})
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusCreated || string(body) != "leader:payload" {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Leader") != "yes" {
		t.Fatalf("response header = %v", resp.Header)
	}
	if _, err := fwd.Forward(context.Background(), nil); err == nil {
		t.Fatal("nil request should fail")
	}
	if _, err := NewForwarder(LeaderForwardConfig{}).Forward(context.Background(), &ForwardRequest{Method: http.MethodPost}); !errors.Is(err, ErrNoLeader) {
		t.Fatalf("forward no leader err = %v", err)
	}

	headers := HopByHopHeaders()
	if len(headers) == 0 || !IsHopByHopHeader("connection") || IsHopByHopHeader("X-Keep") {
		t.Fatalf("hop-by-hop helpers = %v", headers)
	}
	headers[0] = "mutated"
	if HopByHopHeaders()[0] == "mutated" {
		t.Fatal("HopByHopHeaders did not return a copy")
	}
}
