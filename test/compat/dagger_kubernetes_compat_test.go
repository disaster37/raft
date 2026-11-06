package compat

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	raft "github.com/disaster37/raft"
	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/fsm"
	"github.com/disaster37/raft/httpext"
	"github.com/disaster37/raft/k8s"
	"github.com/disaster37/raft/observ"
	"github.com/disaster37/raft/storage"
	"github.com/disaster37/raft/testutil"
)

type sessionSink struct {
	registered map[string]json.RawMessage
	touched    map[string]time.Time
}

func (s *sessionSink) ApplySessionRegistered(id string, payload json.RawMessage, _ time.Time) {
	if s.registered == nil {
		s.registered = map[string]json.RawMessage{}
	}
	s.registered[id] = payload
}
func (s *sessionSink) ApplySessionTouched(id string, at time.Time) {
	if s.touched == nil {
		s.touched = map[string]time.Time{}
	}
	s.touched[id] = at
}

func discardLogger() observ.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return observ.NewLogrusAdapter(l)
}

func TestDaggerKubernetesCompat(t *testing.T) {
	// Config adapter.
	cfg := config.FromDaggerKubernetes(config.DaggerKubernetesConfig{
		Dir:                   t.TempDir(),
		NodeID:                "node-0",
		BindAddr:              "127.0.0.1:0",
		Replicas:              1,
		TLSEnabled:            true,
		CASecret:              "ca",
		AutopilotEnabled:      true,
		CleanupDeadServers:    true,
		MinQuorum:             1,
		PerformanceMultiplier: 5,
		TransportMaxPool:      1,
	})
	if cfg.Storage.Backend != config.StorageBackendRaftBoltDB || !cfg.TLS.AllowAutoCAMultiNode {
		t.Fatalf("adapter = %+v", cfg)
	}

	// Secret bootstrap with a fake clientset.
	client := fake.NewSimpleClientset()
	provider := k8s.NewSecretBootstrapProvider(k8s.SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", CABootstrap: true, CAValidity: time.Hour,
	})
	mat, err := provider.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if len(mat.CACertPEM) == 0 {
		t.Fatal("missing CA")
	}
	secret, err := client.CoreV1().Secrets("ns").Get(context.Background(), "ca", metav1.GetOptions{})
	if err != nil || len(secret.Data["ca.crt"]) == 0 {
		t.Fatalf("secret = %+v err=%v", secret, err)
	}

	// Session sink replication through the in-memory FSM.
	sink := &sessionSink{}
	ln := testutil.FreeListener(t)
	addr := testutil.FreeAddrFromListener(t, ln)
	nodeCfg := config.DefaultConfig()
	nodeCfg.PerformanceMultiplier = 0.2
	nodeCfg.Dir = t.TempDir()
	nodeCfg.NodeID = "node-0"
	nodeCfg.BindAddr = addr
	nodeCfg.AdvertiseAddr = addr
	nodeCfg.Storage.Backend = config.StorageBackendInmem
	nodeCfg.Autopilot.Enabled = false
	nodeCfg.Join.Interval = 100 * time.Millisecond
	n, err := raft.NewNode(context.Background(), &nodeCfg, raft.NodeOptions{CustomListener: ln, SessionSink: sink, Logger: discardLogger()})
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
	if err := n.WaitForCleanState(ctx); err != nil {
		t.Fatalf("WaitForCleanState: %v", err)
	}
	if _, err := n.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "sessions", Key: "s1", Value: []byte(`{"id":"s1"}`)}); err != nil {
		t.Fatalf("apply session: %v", err)
	}
	if _, ok := sink.registered["s1"]; !ok {
		t.Fatal("session sink not invoked")
	}

	// Leader forwarding.
	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("leader"))
	}))
	defer leader.Close()
	_, portStr, _ := net.SplitHostPort(leader.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	handler := httpext.LeaderForwardMiddleware(httpext.LeaderForwardConfig{
		LeaderInfo: fakeLeader{addr: leader.Listener.Addr().String()},
		TargetPort: port,
		Scheme:     "http",
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local"))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/traces", nil))
	if rec.Body.String() != "leader" {
		t.Fatalf("forward body = %q", rec.Body.String())
	}

	// HKDF at-rest sealer from a raw passphrase.
	keeper, err := storage.DeriveAESGCMKeeper([]byte("0123456789abcdef"), storage.DefaultHKDFInfo, storage.DefaultHKDFInfo)
	if err != nil {
		t.Fatalf("derive keeper: %v", err)
	}
	sealed, err := keeper.SealString("secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if opened, err := keeper.OpenString(sealed); err != nil || opened != "secret" {
		t.Fatalf("open = %q err=%v", opened, err)
	}

	// Framework-agnostic forwarder and probe helpers used by Hertz handlers.
	fwd := httpext.NewForwarder(httpext.LeaderForwardConfig{
		LeaderInfo: fakeLeader{addr: leader.Listener.Addr().String()},
		TargetPort: port,
		Scheme:     "http",
	})
	if !fwd.ShouldForward(http.MethodPost, "/api/v1/traces", "") {
		t.Fatal("POST should forward")
	}
	if fwd.ShouldForward(http.MethodGet, "/api/v1/traces", "") {
		t.Fatal("GET should not forward")
	}
	if code, body := httpext.ReadyzStatus(fakeReadiness{clean: true}); code != http.StatusOK || body != "ok" {
		t.Fatalf("readyz = %d %q", code, body)
	}
	if code, _ := httpext.StartupStatus(fakeReadiness{}); code != http.StatusServiceUnavailable {
		t.Fatalf("startup = %d", code)
	}
	if code, body := httpext.LivezStatus(); code != http.StatusOK || body != "ok" {
		t.Fatalf("livez = %d %q", code, body)
	}
}

type fakeLeader struct {
	addr string
}

type fakeReadiness struct {
	clean   bool
	started bool
}

func (f fakeReadiness) IsCleanState() bool { return f.clean }
func (f fakeReadiness) IsStarted() bool    { return f.started }

func (f fakeLeader) IsLeader() bool        { return false }
func (f fakeLeader) LeaderAddress() string { return f.addr }

func TestDaggerKubernetesSecretFollowerPoll(t *testing.T) {
	client := fake.NewSimpleClientset()
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = client.CoreV1().Secrets("ns").Create(context.Background(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
			Data:       map[string][]byte{"ca.crt": []byte("cert"), "ca.key": []byte("key")},
		}, metav1.CreateOptions{})
	}()
	provider := k8s.NewSecretBootstrapProvider(k8s.SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", PollTimeout: time.Second, PollInterval: 10 * time.Millisecond,
	})
	mat, err := provider.EnsureBootstrapMaterial(context.Background())
	if err != nil || string(mat.CACertPEM) != "cert" {
		t.Fatalf("mat = %+v err=%v", mat, err)
	}
}
