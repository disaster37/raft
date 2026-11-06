package keyring

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/pki"
	"github.com/disaster37/raft/storage"
	"github.com/disaster37/raft/transport"
)

func TestGenerateTLSKeyWithGocaSharedCAAndSelfSigned(t *testing.T) {
	now := time.Now()
	for _, mode := range []config.PKIMode{config.PKIModeSharedCA, config.PKIModeSelfSigned} {
		key, err := GenerateTLSKeyWithGoca(mode, "node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, nil, now)
		if err != nil {
			t.Fatalf("GenerateTLSKeyWithGoca(%s): %v", mode, err)
		}
		if key.ID == "" || len(key.CertPEM) == 0 || key.KeyPEM == "" {
			t.Fatalf("key = %+v", key)
		}
		if key.PKIMode != string(mode) || !key.IsCA {
			t.Fatalf("key = %+v", key)
		}
		if _, err := key.ParseCert(); err != nil {
			t.Fatalf("ParseCert: %v", err)
		}
	}
	if _, err := GenerateTLSKeyWithGoca("bad", "node", "org", nil, nil, time.Hour, nil, now); err == nil {
		t.Fatal("expected error for bad mode")
	}
}

func TestTLSKeyringValidation(t *testing.T) {
	valid := &TLSKeyring{Keys: []*TLSKey{{ID: "k1", PKIMode: "shared-ca", CertPEM: []byte("c")}}, ActiveKeyID: "k1", Term: 1}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid keyring: %v", err)
	}
	if valid.GetActive() == nil {
		t.Fatal("missing active")
	}
	if valid.Clone() == nil {
		t.Fatal("clone nil")
	}
	var nilKeyring *TLSKeyring
	if nilKeyring.Clone() != nil || nilKeyring.GetActive() != nil {
		t.Fatal("nil keyring helpers")
	}
	tests := []*TLSKeyring{
		nil,
		{},
		{Keys: []*TLSKey{{ID: "k1", PKIMode: "shared-ca", CertPEM: []byte("c")}}, ActiveKeyID: "k1", Term: 0},
		{Keys: []*TLSKey{{ID: "k1", PKIMode: "shared-ca", CertPEM: []byte("c")}}, ActiveKeyID: "missing", Term: 1},
		{Keys: []*TLSKey{{ID: "", PKIMode: "shared-ca", CertPEM: []byte("c")}}, ActiveKeyID: "", Term: 1},
		{Keys: []*TLSKey{{ID: "k1", PKIMode: "shared-ca"}}, ActiveKeyID: "k1", Term: 1},
		{Keys: []*TLSKey{{ID: "k1", PKIMode: "bad", CertPEM: []byte("c")}}, ActiveKeyID: "k1", Term: 1},
		{Keys: []*TLSKey{nil}, ActiveKeyID: "k1", Term: 1},
		{Keys: []*TLSKey{{ID: "k1", PKIMode: "shared-ca", CertPEM: []byte("c")}, {ID: "k2", PKIMode: "shared-ca", CertPEM: []byte("c")}, {ID: "k3", PKIMode: "shared-ca", CertPEM: []byte("c")}}, ActiveKeyID: "k1", Term: 1},
	}
	for i, kr := range tests {
		if err := kr.Validate(); err == nil {
			t.Fatalf("case %d expected error", i)
		}
	}
}

func TestManagerDualTrustAndKeySwap(t *testing.T) {
	dir := t.TempDir()
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	swaps := 0
	manager, err := NewManager(ManagerConfig{
		Dir:            dir,
		PKIMode:        config.PKIModeSharedCA,
		NodeCommonName: "node",
		Organization:   "org",
		DNSNames:       []string{"localhost"},
		IPAddrs:        []net.IP{net.ParseIP("127.0.0.1")},
		LeafValidity:   time.Hour,
		SafetyMargin:   time.Minute,
		TLSProvider:    provider,
		DisconnectOnSwap: func() {
			swaps++
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	key1, err := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca1", "org", nil, nil, time.Hour, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kr1 := &TLSKeyring{Keys: []*TLSKey{key1}, ActiveKeyID: key1.ID, Term: 1}
	if err := manager.SetTLSKeyring(kr1); err != nil {
		t.Fatalf("SetTLSKeyring: %v", err)
	}
	if manager.CurrentKeyring() == nil || manager.CurrentKeyring().Term != 1 {
		t.Fatal("keyring not installed")
	}
	if provider.CurrentCertPool() == nil {
		t.Fatal("provider pool not updated")
	}
	// Same term is a fast no-op.
	if err := manager.SetTLSKeyring(kr1); err != nil {
		t.Fatal(err)
	}

	key2, err := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca2", "org", nil, nil, time.Hour, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kr2 := &TLSKeyring{Keys: []*TLSKey{key1, key2}, ActiveKeyID: key1.ID, Term: 2}
	if err := manager.SetTLSKeyring(kr2); err != nil {
		t.Fatalf("dual trust: %v", err)
	}
	if swaps != 0 {
		t.Fatalf("unexpected swap during dual trust: %d", swaps)
	}
	kr3 := &TLSKeyring{Keys: []*TLSKey{key2}, ActiveKeyID: key2.ID, Term: 3}
	if err := manager.SetTLSKeyring(kr3); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if swaps != 1 {
		t.Fatalf("swaps = %d, want 1", swaps)
	}
	manager.DropBootstrapTrust()
	if err := manager.SetTLSKeyring(nil); err == nil {
		t.Fatal("expected nil keyring error")
	}
}

func TestManagerSelfSigned(t *testing.T) {
	dir := t.TempDir()
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, err := NewManager(ManagerConfig{
		Dir:            dir,
		PKIMode:        config.PKIModeSelfSigned,
		NodeCommonName: "node",
		Organization:   "org",
		TLSProvider:    provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateTLSKeyWithGoca(config.PKIModeSelfSigned, "node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kr := &TLSKeyring{Keys: []*TLSKey{key}, ActiveKeyID: key.ID, Term: 1}
	if err := manager.SetTLSKeyring(kr); err != nil {
		t.Fatalf("SetTLSKeyring: %v", err)
	}
	if provider.CurrentCertPool() == nil {
		t.Fatal("pool not updated")
	}
}

func TestNewManagerErrors(t *testing.T) {
	if _, err := NewManager(ManagerConfig{}); err == nil {
		t.Fatal("expected error for nil provider")
	}
}

type fakeApplier struct {
	mu       sync.Mutex
	leader   bool
	applied  uint64
	minIndex uint64
	kr       *TLSKeyring
}

func (f *fakeApplier) IsLeader() bool { return f.leader }
func (f *fakeApplier) AppliedIndex() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied
}
func (f *fakeApplier) MinFollowerAppliedIndex() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.minIndex
}
func (f *fakeApplier) ReadKeyring() (*TLSKeyring, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.kr.Clone(), nil
}
func (f *fakeApplier) ApplyKeyring(_ context.Context, kr *TLSKeyring) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied++
	f.kr = kr.Clone()
	return f.applied, nil
}

func TestPhasedRotatorPhase1AndPhase2(t *testing.T) {
	applier := &fakeApplier{leader: true}
	now := time.Now()
	rotator := NewPhasedRotator(RotatorConfig{
		PKIMode:        config.PKIModeSharedCA,
		CommonName:     "node",
		Organization:   "org",
		Validity:       time.Hour,
		RotationPeriod: time.Hour,
		CheckInterval:  time.Millisecond,
		Applier:        applier,
		NowFunc:        func() time.Time { return now },
	})
	if _, err := rotator.RotateOnce(context.Background()); err != nil {
		t.Fatalf("initial rotate: %v", err)
	}
	kr := applier.kr
	if kr == nil || kr.Term != 1 || len(kr.Keys) != 1 {
		t.Fatalf("initial keyring = %+v", kr)
	}
	// Not due yet.
	if _, err := rotator.RotateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(applier.kr.Keys) != 1 {
		t.Fatal("rotation happened too early")
	}
	// Advance past the rotation period.
	now = now.Add(2 * time.Hour)
	if _, err := rotator.RotateOnce(context.Background()); err != nil {
		t.Fatalf("stage: %v", err)
	}
	kr = applier.kr
	if kr.Term != 2 || len(kr.Keys) != 2 {
		t.Fatalf("staged keyring = %+v", kr)
	}
	// Complete Phase 1 Write 2 on the next tick.
	if _, err := rotator.RotateOnce(context.Background()); err != nil {
		t.Fatalf("complete phase 1: %v", err)
	}
	kr = applier.kr
	if kr.AppliedIndex == 0 || kr.Keys[1].AppliedIndex == 0 {
		t.Fatalf("phase 1 not committed: %+v", kr)
	}
	// Lagging follower blocks activation.
	applier.minIndex = kr.AppliedIndex - 1
	activated, err := rotator.CheckCommitted(context.Background())
	if err != nil || activated {
		t.Fatalf("activated=%v err=%v", activated, err)
	}
	applier.minIndex = kr.AppliedIndex
	activated, err = rotator.CheckCommitted(context.Background())
	if err != nil || !activated {
		t.Fatalf("activated=%v err=%v", activated, err)
	}
	kr = applier.kr
	if kr.Term != 3 || len(kr.Keys) != 1 || kr.ActiveKeyID != kr.Keys[0].ID {
		t.Fatalf("activated keyring = %+v", kr)
	}
}

func TestPhasedRotatorRecoversInterruptedWrite2(t *testing.T) {
	key1, err := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca1", "org", nil, nil, time.Hour, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key2, err := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca2", "org", nil, nil, time.Hour, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	applier := &fakeApplier{
		leader:  true,
		applied: 10,
		kr:      &TLSKeyring{Keys: []*TLSKey{key1, key2}, ActiveKeyID: key1.ID, Term: 2},
	}
	rotator := NewPhasedRotator(RotatorConfig{
		PKIMode:        config.PKIModeSharedCA,
		CommonName:     "node",
		Organization:   "org",
		Validity:       time.Hour,
		RotationPeriod: time.Hour,
		Applier:        applier,
	})
	if _, err := rotator.RotateOnce(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if applier.kr.AppliedIndex != 10 || applier.kr.Keys[1].AppliedIndex != 10 {
		t.Fatalf("keyring = %+v", applier.kr)
	}
}

func TestPhasedRotatorNotLeader(t *testing.T) {
	applier := &fakeApplier{leader: false}
	rotator := NewPhasedRotator(RotatorConfig{Applier: applier})
	if _, err := rotator.RotateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if activated, err := rotator.CheckCommitted(context.Background()); err != nil || activated {
		t.Fatalf("activated=%v err=%v", activated, err)
	}
}

func emptyLeaf() tls.Certificate { return tls.Certificate{} }

func TestKeyringFromBootstrapCA(t *testing.T) {
	ca, err := pki.NewMintingCA("ca", "org", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.EncodePEM()
	if err != nil {
		t.Fatal(err)
	}
	mat := &pki.BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}
	kr, err := KeyringFromBootstrapCA(config.PKIModeSharedCA, mat, nil, time.Now())
	if err != nil {
		t.Fatalf("KeyringFromBootstrapCA: %v", err)
	}
	if kr.Term != 1 || len(kr.Keys) != 1 || kr.ActiveKeyID != kr.Keys[0].ID {
		t.Fatalf("keyring = %+v", kr)
	}
	if _, err := KeyringFromBootstrapCA(config.PKIModeSharedCA, nil, nil, time.Now()); err == nil {
		t.Fatal("expected nil material error")
	}
	if _, err := KeyringFromBootstrapCA(config.PKIModeSharedCA, &pki.BootstrapMaterial{CACertPEM: []byte("bad")}, nil, time.Now()); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestPhasedRotatorStart(t *testing.T) {
	applier := &fakeApplier{leader: true}
	rotator := NewPhasedRotator(RotatorConfig{
		PKIMode:        config.PKIModeSharedCA,
		CommonName:     "node",
		Organization:   "org",
		Validity:       time.Hour,
		RotationPeriod: time.Hour,
		CheckInterval:  time.Millisecond,
		Applier:        applier,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rotator.Start(ctx)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if applier.kr == nil {
		t.Fatal("rotator did not seed keyring")
	}
}

func TestManagerSealerAndErrors(t *testing.T) {
	dir := t.TempDir()
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	sealer, err := storage.NewAESGCMKeeper("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "aad")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(ManagerConfig{
		Dir:            dir,
		PKIMode:        config.PKIModeSharedCA,
		NodeCommonName: "node",
		Organization:   "org",
		DNSNames:       []string{"localhost"},
		IPAddrs:        []net.IP{net.ParseIP("127.0.0.1")},
		LeafValidity:   time.Hour,
		SafetyMargin:   time.Minute,
		Sealer:         sealer,
		TLSProvider:    provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca", "org", nil, nil, time.Hour, sealer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kr := &TLSKeyring{Keys: []*TLSKey{key}, ActiveKeyID: key.ID, Term: 1}
	if err := manager.SetTLSKeyring(kr); err != nil {
		t.Fatalf("SetTLSKeyring with sealer: %v", err)
	}
	if err := manager.SetTLSKeyring(&TLSKeyring{Keys: []*TLSKey{{ID: "bad", PKIMode: "shared-ca", CertPEM: []byte("bad")}}, ActiveKeyID: "bad", Term: 2}); err == nil {
		t.Fatal("expected invalid keyring error")
	}
}

type errorApplier struct {
	fakeApplier
	readErr  error
	applyErr error
}

func (e *errorApplier) ReadKeyring() (*TLSKeyring, error) {
	if e.readErr != nil {
		return nil, e.readErr
	}
	return e.fakeApplier.ReadKeyring()
}

func (e *errorApplier) ApplyKeyring(ctx context.Context, kr *TLSKeyring) (uint64, error) {
	if e.applyErr != nil {
		return 0, e.applyErr
	}
	return e.fakeApplier.ApplyKeyring(ctx, kr)
}

func TestRotatorErrorPaths(t *testing.T) {
	rotator := NewPhasedRotator(RotatorConfig{Applier: &errorApplier{fakeApplier: fakeApplier{leader: true}, readErr: errors.New("read")}})
	if _, err := rotator.RotateOnce(context.Background()); err == nil {
		t.Fatal("expected read error")
	}
	rotator = NewPhasedRotator(RotatorConfig{Applier: &errorApplier{fakeApplier: fakeApplier{leader: true}, applyErr: errors.New("apply")}})
	if _, err := rotator.RotateOnce(context.Background()); err == nil {
		t.Fatal("expected apply error")
	}
	applier := &fakeApplier{leader: true, kr: &TLSKeyring{Keys: []*TLSKey{{ID: "a"}, {ID: "b"}, {ID: "c"}}, ActiveKeyID: "a", Term: 1}}
	rotator = NewPhasedRotator(RotatorConfig{Applier: applier})
	if _, err := rotator.RotateOnce(context.Background()); err == nil {
		t.Fatal("expected too many keys error")
	}
	applier = &fakeApplier{leader: true, kr: &TLSKeyring{Keys: []*TLSKey{{ID: "a"}}, ActiveKeyID: "missing", Term: 1}}
	rotator = NewPhasedRotator(RotatorConfig{Applier: applier})
	if _, err := rotator.RotateOnce(context.Background()); err == nil {
		t.Fatal("expected missing active key error")
	}
	applier = &fakeApplier{leader: true, kr: &TLSKeyring{Keys: []*TLSKey{{ID: "a", CreatedTime: time.Now()}}, ActiveKeyID: "a", Term: 1}}
	rotator = NewPhasedRotator(RotatorConfig{Applier: applier, RotationPeriod: time.Hour})
	if _, err := rotator.RotateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// CheckCommitted apply error.
	rotator = NewPhasedRotator(RotatorConfig{Applier: &errorApplier{fakeApplier: fakeApplier{leader: true, kr: &TLSKeyring{Keys: []*TLSKey{{ID: "a"}, {ID: "b"}}, ActiveKeyID: "a", Term: 2, AppliedIndex: 1}, minIndex: 1}, applyErr: errors.New("apply")}})
	if _, err := rotator.CheckCommitted(context.Background()); err == nil {
		t.Fatal("expected activation error")
	}
}

func TestRotatorStartWithErrors(t *testing.T) {
	applier := &errorApplier{readErr: errors.New("read")}
	applier.leader = true
	rotator := NewPhasedRotator(RotatorConfig{Applier: applier, CheckInterval: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rotator.Start(ctx)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done
}

func TestKeyringFromBootstrapCAWithSealer(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.EncodePEM()
	sealer, _ := storage.NewAESGCMKeeper("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "aad")
	kr, err := KeyringFromBootstrapCA(config.PKIModeSharedCA, &pki.BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}, sealer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if kr.Keys[0].KeyPEM == string(keyPEM) {
		t.Fatal("key was not sealed")
	}
}

func TestGenerateTLSKeyWithGocaSealerAndErrors(t *testing.T) {
	sealer, _ := storage.NewAESGCMKeeper("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "aad")
	key, err := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca", "org", nil, nil, time.Hour, sealer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyPEM == "" {
		t.Fatal("missing sealed key")
	}
	if _, err := GenerateTLSKeyWithGoca("bad", "ca", "org", nil, nil, time.Hour, nil, time.Now()); err == nil {
		t.Fatal("expected bad mode error")
	}
}

func TestManagerErrorPaths(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, err := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSharedCA, TLSProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	// Shared CA key with no private key.
	kr := &TLSKeyring{Keys: []*TLSKey{{ID: "k", PKIMode: "shared-ca", CertPEM: []byte("bad")}}, ActiveKeyID: "k", Term: 1}
	if err := manager.SetTLSKeyring(kr); err == nil {
		t.Fatal("expected invalid cert error")
	}
	// Unsupported PKI mode.
	kr = &TLSKeyring{Keys: []*TLSKey{{ID: "k", PKIMode: "bad", CertPEM: []byte("bad")}}, ActiveKeyID: "k", Term: 1}
	if err := manager.SetTLSKeyring(kr); err == nil {
		t.Fatal("expected unsupported mode error")
	}
	// Self-signed invalid key.
	kr = &TLSKeyring{Keys: []*TLSKey{{ID: "k", PKIMode: "self-signed", CertPEM: []byte("bad"), KeyPEM: "bad"}}, ActiveKeyID: "k", Term: 1}
	if err := manager.SetTLSKeyring(kr); err == nil {
		t.Fatal("expected self-signed parse error")
	}
	// Sealer error.
	badSealer := &failingSealer{}
	manager, _ = NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSharedCA, TLSProvider: provider, Sealer: badSealer})
	kr = &TLSKeyring{Keys: []*TLSKey{{ID: "k", PKIMode: "shared-ca", CertPEM: []byte("bad"), KeyPEM: "sealed"}}, ActiveKeyID: "k", Term: 1}
	if err := manager.SetTLSKeyring(kr); err == nil {
		t.Fatal("expected sealer error")
	}
	manager.DropBootstrapTrust()
}

type failingSealer struct{}

func (failingSealer) Seal([]byte) (storage.EncryptedValue, error) {
	return storage.EncryptedValue{}, errors.New("seal")
}
func (failingSealer) Open(storage.EncryptedValue) ([]byte, error) { return nil, errors.New("open") }
func (failingSealer) SealString(string) (string, error)           { return "", errors.New("seal") }
func (failingSealer) OpenString(string) (string, error)           { return "", errors.New("open") }

func TestManagerLeavesForBranches(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, _ := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSharedCA, TLSProvider: provider})
	kr := &TLSKeyring{Keys: []*TLSKey{{ID: "k", PKIMode: "shared-ca", CertPEM: []byte("bad")}}, ActiveKeyID: "k", Term: 1}
	if _, _, err := manager.leavesFor(kr, kr.Keys[0]); err == nil {
		t.Fatal("expected empty key error")
	}
	kr = &TLSKeyring{Keys: []*TLSKey{{ID: "k", PKIMode: "self-signed", CertPEM: []byte("bad"), KeyPEM: "bad"}}, ActiveKeyID: "k", Term: 1}
	if _, _, err := manager.leavesFor(kr, kr.Keys[0]); err == nil {
		t.Fatal("expected self-signed error")
	}
	kr = &TLSKeyring{Keys: []*TLSKey{{ID: "k", PKIMode: "bad", CertPEM: []byte("bad")}}, ActiveKeyID: "k", Term: 1}
	if _, _, err := manager.leavesFor(kr, kr.Keys[0]); err == nil {
		t.Fatal("expected unsupported mode error")
	}
}

func TestManagerUnsealBranches(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, _ := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSharedCA, TLSProvider: provider})
	if got, err := manager.unseal(""); err != nil || got != nil {
		t.Fatalf("unseal empty = %v err=%v", got, err)
	}
	if got, err := manager.unseal("plain"); err != nil || string(got) != "plain" {
		t.Fatalf("unseal plain = %q err=%v", got, err)
	}
	manager.cfg.Sealer = failingSealer{}
	if _, err := manager.unseal("sealed"); err == nil {
		t.Fatal("expected sealer error")
	}
}

func TestManagerTrustedPoolNilKey(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, _ := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSharedCA, TLSProvider: provider})
	kr := &TLSKeyring{Keys: []*TLSKey{nil}, ActiveKeyID: "k", Term: 1}
	if _, err := manager.trustedPool(kr); err != nil {
		t.Fatalf("trustedPool: %v", err)
	}
}

func TestRotatorSeedAndApplyErrors(t *testing.T) {
	seedErr := NewPhasedRotator(RotatorConfig{Applier: &fakeApplier{leader: true}, Seed: func(context.Context) (*TLSKeyring, error) {
		return nil, errors.New("seed")
	}})
	if _, err := seedErr.RotateOnce(context.Background()); err == nil {
		t.Fatal("expected seed error")
	}
	seedNil := NewPhasedRotator(RotatorConfig{Applier: &fakeApplier{leader: true}, Seed: func(context.Context) (*TLSKeyring, error) {
		return nil, nil
	}})
	if _, err := seedNil.RotateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	applyErr := NewPhasedRotator(RotatorConfig{Applier: &errorApplier{fakeApplier: fakeApplier{leader: true}, applyErr: errors.New("apply")}})
	if _, err := applyErr.RotateOnce(context.Background()); err == nil {
		t.Fatal("expected initial apply error")
	}
	// Complete phase 1 apply error.
	key1, _ := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca", "org", nil, nil, time.Hour, nil, time.Now())
	key2, _ := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca", "org", nil, nil, time.Hour, nil, time.Now())
	applier := &errorApplier{fakeApplier: fakeApplier{leader: true, kr: &TLSKeyring{Keys: []*TLSKey{key1, key2}, ActiveKeyID: key1.ID, Term: 2}}, applyErr: errors.New("apply")}
	rotator := NewPhasedRotator(RotatorConfig{Applier: applier})
	if _, err := rotator.RotateOnce(context.Background()); err == nil {
		t.Fatal("expected phase 1 apply error")
	}
	// Stage apply error.
	applier = &errorApplier{fakeApplier: fakeApplier{leader: true, kr: &TLSKeyring{Keys: []*TLSKey{key1}, ActiveKeyID: key1.ID, Term: 1}}, applyErr: errors.New("apply")}
	rotator = NewPhasedRotator(RotatorConfig{Applier: applier, RotationPeriod: time.Nanosecond})
	if _, err := rotator.RotateOnce(context.Background()); err == nil {
		t.Fatal("expected stage apply error")
	}
}

func TestGenerateTLSKeySealerError(t *testing.T) {
	if _, err := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca", "org", nil, nil, time.Hour, failingSealer{}, time.Now()); err == nil {
		t.Fatal("expected sealer error")
	}
}

func TestKeyringFromBootstrapCASealerError(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.EncodePEM()
	if _, err := KeyringFromBootstrapCA(config.PKIModeSharedCA, &pki.BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}, failingSealer{}, time.Now()); err == nil {
		t.Fatal("expected sealer error")
	}
}

func TestDropBootstrapTrustNoCurrent(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, _ := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSharedCA, TLSProvider: provider})
	manager.DropBootstrapTrust()
}

func TestGenerateTLSKeySelfSignedWithSealerAndDefaults(t *testing.T) {
	sealer, _ := storage.NewAESGCMKeeper("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "aad")
	key, err := GenerateTLSKeyWithGoca(config.PKIModeSelfSigned, "", "", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, sealer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyPEM == "" || key.ID == "" {
		t.Fatalf("key = %+v", key)
	}
}

func TestManagerLeavesForSelfSignedActiveSecond(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, _ := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSelfSigned, TLSProvider: provider})
	k1, _ := GenerateTLSKeyWithGoca(config.PKIModeSelfSigned, "a", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, nil, time.Now())
	k2, _ := GenerateTLSKeyWithGoca(config.PKIModeSelfSigned, "b", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, nil, time.Now())
	kr := &TLSKeyring{Keys: []*TLSKey{k1, k2}, ActiveKeyID: k2.ID, Term: 1}
	if _, all, err := manager.leavesFor(kr, k2); err != nil || len(all) != 2 {
		t.Fatalf("leaves = %d err=%v", len(all), err)
	}
}

func TestManagerApplyKeyringActiveNil(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, _ := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSharedCA, TLSProvider: provider})
	kr := &TLSKeyring{Keys: []*TLSKey{{ID: "k", PKIMode: "shared-ca", CertPEM: []byte("bad")}}, ActiveKeyID: "missing", Term: 1}
	if err := manager.applyKeyring(kr); err == nil {
		t.Fatal("expected missing active error")
	}
}

func TestManagerDropBootstrapTrustApplyError(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, _ := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSharedCA, TLSProvider: provider})
	manager.current = &TLSKeyring{Keys: []*TLSKey{{ID: "k", PKIMode: "shared-ca", CertPEM: []byte("bad")}}, ActiveKeyID: "k", Term: 1}
	manager.DropBootstrapTrust()
}

func TestKeyringFromBootstrapCAEmptyKey(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, _, _ := ca.EncodePEM()
	kr, err := KeyringFromBootstrapCA(config.PKIModeSharedCA, &pki.BootstrapMaterial{CACertPEM: certPEM}, nil, time.Now())
	if err != nil || kr.Keys[0].KeyPEM != "" {
		t.Fatalf("kr = %+v err=%v", kr, err)
	}
}

func TestSelfSignedLeafEmptyKey(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, _ := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSelfSigned, TLSProvider: provider})
	if _, err := manager.selfSignedLeaf(&TLSKey{ID: "k", CertPEM: []byte("bad")}); err == nil {
		t.Fatal("expected empty key error")
	}
}

func TestCloneNilKey(t *testing.T) {
	kr := &TLSKeyring{Keys: []*TLSKey{nil, {ID: "k", CertPEM: []byte("c")}}, ActiveKeyID: "k", Term: 1}
	clone := kr.Clone()
	if len(clone.Keys) != 1 {
		t.Fatalf("clone keys = %d", len(clone.Keys))
	}
}

func TestRotateOnceTwoKeysCommitted(t *testing.T) {
	k1, _ := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "a", "org", nil, nil, time.Hour, nil, time.Now())
	k2, _ := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "b", "org", nil, nil, time.Hour, nil, time.Now())
	applier := &fakeApplier{leader: true, kr: &TLSKeyring{Keys: []*TLSKey{k1, k2}, ActiveKeyID: k1.ID, Term: 2, AppliedIndex: 5}}
	rotator := NewPhasedRotator(RotatorConfig{Applier: applier})
	if _, err := rotator.RotateOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateTLSKeyInjectedErrors(t *testing.T) {
	origCA, origSANs, origID := newMintingCA, newMintingCAWithSANs, newKeyID
	t.Cleanup(func() { newMintingCA, newMintingCAWithSANs, newKeyID = origCA, origSANs, origID })
	newMintingCA = func(string, string, time.Duration) (*pki.MintingCA, error) { return nil, errors.New("ca") }
	if _, err := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca", "org", nil, nil, time.Hour, nil, time.Now()); err == nil {
		t.Fatal("expected shared CA error")
	}
	newMintingCAWithSANs = func(string, string, []string, []net.IP, time.Duration) (*pki.MintingCA, error) {
		return nil, errors.New("sans")
	}
	if _, err := GenerateTLSKeyWithGoca(config.PKIModeSelfSigned, "ca", "org", nil, nil, time.Hour, nil, time.Now()); err == nil {
		t.Fatal("expected self-signed error")
	}
	newMintingCA = origCA
	newMintingCAWithSANs = origSANs
	newKeyID = func() (string, error) { return "", errors.New("id") }
	if _, err := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca", "org", nil, nil, time.Hour, nil, time.Now()); err == nil {
		t.Fatal("expected key id error")
	}
}

func TestKeyringFromBootstrapCAInjectedErrors(t *testing.T) {
	origParse, origID := parsePEMCert, newKeyID
	t.Cleanup(func() { parsePEMCert, newKeyID = origParse, origID })
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.EncodePEM()
	parsePEMCert = func([]byte) (*x509.Certificate, error) { return nil, errors.New("parse") }
	if _, err := KeyringFromBootstrapCA(config.PKIModeSharedCA, &pki.BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}, nil, time.Now()); err == nil {
		t.Fatal("expected parse error")
	}
	parsePEMCert = origParse
	newKeyID = func() (string, error) { return "", errors.New("id") }
	if _, err := KeyringFromBootstrapCA(config.PKIModeSharedCA, &pki.BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}, nil, time.Now()); err == nil {
		t.Fatal("expected key id error")
	}
}

func TestManagerInjectedErrors(t *testing.T) {
	origCA, origIssue, origPair := newMintingCAFromPEM, issueOrReuseNodeCert, x509KeyPair
	t.Cleanup(func() { newMintingCAFromPEM, issueOrReuseNodeCert, x509KeyPair = origCA, origIssue, origPair })
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, _ := NewManager(ManagerConfig{Dir: t.TempDir(), PKIMode: config.PKIModeSharedCA, TLSProvider: provider})
	key, _ := GenerateTLSKeyWithGoca(config.PKIModeSharedCA, "ca", "org", nil, nil, time.Hour, nil, time.Now())
	kr := &TLSKeyring{Keys: []*TLSKey{key}, ActiveKeyID: key.ID, Term: 1}
	newMintingCAFromPEM = func([]byte, []byte, time.Duration) (*pki.MintingCA, error) { return nil, errors.New("ca") }
	if err := manager.SetTLSKeyring(kr); err == nil {
		t.Fatal("expected CA load error")
	}
	newMintingCAFromPEM = origCA
	issueOrReuseNodeCert = func(string, *pki.MintingCA, string, string, []string, []net.IP, time.Duration, time.Duration) ([]byte, []byte, error) {
		return nil, nil, errors.New("issue")
	}
	if err := manager.SetTLSKeyring(kr); err == nil {
		t.Fatal("expected issue error")
	}
	issueOrReuseNodeCert = origIssue
	x509KeyPair = func([]byte, []byte) (tls.Certificate, error) { return tls.Certificate{}, errors.New("pair") }
	if err := manager.SetTLSKeyring(kr); err == nil {
		t.Fatal("expected key pair error")
	}
}

func TestNewManagerDefaults(t *testing.T) {
	provider := transport.NewDynamicTLSProvider(emptyLeaf(), nil, nil, true)
	manager, err := NewManager(ManagerConfig{TLSProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	if manager.cfg.PKIMode != config.PKIModeSharedCA || manager.cfg.LeafValidity == 0 || manager.cfg.SafetyMargin == 0 {
		t.Fatalf("defaults = %+v", manager.cfg)
	}
}
