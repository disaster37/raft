package keyring

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/disaster37/go-raft/config"
	"github.com/disaster37/go-raft/observ"
	"github.com/disaster37/go-raft/pki"
	"github.com/disaster37/go-raft/storage"
	"github.com/disaster37/go-raft/transport"
)

var (
	newMintingCAFromPEM  = pki.NewMintingCAFromPEM
	issueOrReuseNodeCert = pki.IssueOrReuseNodeCert
	x509KeyPair          = tls.X509KeyPair
)

// ManagerConfig configures a keyring Manager.
type ManagerConfig struct {
	Dir              string
	PKIMode          config.PKIMode
	NodeCommonName   string
	Organization     string
	DNSNames         []string
	IPAddrs          []net.IP
	LeafValidity     time.Duration
	SafetyMargin     time.Duration
	Sealer           storage.Sealer
	TLSProvider      *transport.DynamicTLSProvider
	BootstrapCACert  *x509.Certificate
	DisconnectOnSwap func()
	Logger           observ.Logger
	Metrics          observ.MetricsCollector
}

// Manager bridges the replicated FSM keyring and the transport's
// DynamicTLSProvider.
type Manager struct {
	cfg       ManagerConfig
	mu        sync.RWMutex
	current   *TLSKeyring
	bootstrap *x509.Certificate
	dropped   bool
}

// NewManager returns a keyring manager.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.TLSProvider == nil {
		return nil, fmt.Errorf("keyring manager: TLS provider is required")
	}
	if cfg.PKIMode == "" {
		cfg.PKIMode = config.PKIModeSharedCA
	}
	if cfg.LeafValidity <= 0 {
		cfg.LeafValidity = 365 * 24 * time.Hour
	}
	if cfg.SafetyMargin <= 0 {
		cfg.SafetyMargin = pki.DefaultSafetyMargin
	}
	if cfg.Logger == nil {
		cfg.Logger = observ.NewNoopLogger()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = observ.NewNoopMetrics()
	}
	return &Manager{cfg: cfg, bootstrap: cfg.BootstrapCACert}, nil
}

// SetTLSKeyring installs a replicated keyring and updates the TLS provider.
func (m *Manager) SetTLSKeyring(kr *TLSKeyring) error {
	if kr == nil {
		return fmt.Errorf("set keyring: nil keyring")
	}
	if err := kr.Validate(); err != nil {
		return fmt.Errorf("set keyring: %w", err)
	}
	m.mu.Lock()
	if m.current != nil && m.current.Term == kr.Term && m.current.AppliedIndex == kr.AppliedIndex {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	return m.applyKeyring(kr)
}

func (m *Manager) applyKeyring(kr *TLSKeyring) error {
	active := kr.GetActive()
	if active == nil {
		return fmt.Errorf("keyring has no active key")
	}
	pool, err := m.trustedPool(kr)
	if err != nil {
		return err
	}
	activeLeaf, allLeaves, err := m.leavesFor(kr, active)
	if err != nil {
		return err
	}

	m.mu.Lock()
	previous := m.current
	m.current = kr.Clone()
	m.mu.Unlock()

	m.cfg.TLSProvider.UpdateKeyringView(activeLeaf, allLeaves, pool)
	if previous != nil && previous.ActiveKeyID != kr.ActiveKeyID && m.cfg.DisconnectOnSwap != nil {
		m.cfg.DisconnectOnSwap()
	}
	m.cfg.Metrics.SetKeyringTerm(kr.Term)
	m.cfg.Metrics.SetKeyringActiveKeyAgeSeconds(time.Since(active.CreatedTime).Seconds())
	m.cfg.Logger.Info("tls keyring installed", map[string]any{
		"term":          kr.Term,
		"active_key_id": kr.ActiveKeyID,
		"keys":          len(kr.Keys),
	})
	return nil
}

func (m *Manager) trustedPool(kr *TLSKeyring) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, key := range kr.Keys {
		if key == nil {
			continue
		}
		if !pool.AppendCertsFromPEM(key.CertPEM) {
			return nil, fmt.Errorf("key %q has no parseable certificate", key.ID)
		}
	}
	m.mu.RLock()
	bootstrap := m.bootstrap
	dropped := m.dropped
	m.mu.RUnlock()
	if bootstrap != nil && !dropped {
		pool.AddCert(bootstrap)
	}
	return pool, nil
}

func (m *Manager) leavesFor(kr *TLSKeyring, active *TLSKey) (tls.Certificate, []tls.Certificate, error) {
	switch config.PKIMode(active.PKIMode) {
	case config.PKIModeSelfSigned:
		all := make([]tls.Certificate, 0, len(kr.Keys))
		var activeLeaf tls.Certificate
		for _, key := range kr.Keys {
			leaf, err := m.selfSignedLeaf(key)
			if err != nil {
				return tls.Certificate{}, nil, err
			}
			all = append(all, leaf)
			if key.ID == active.ID {
				activeLeaf = leaf
			}
		}
		return activeLeaf, all, nil
	case config.PKIModeSharedCA:
		keyPEM, err := m.unseal(active.KeyPEM)
		if err != nil {
			return tls.Certificate{}, nil, err
		}
		if len(keyPEM) == 0 {
			return tls.Certificate{}, nil, fmt.Errorf("active shared CA key %q has no private key", active.ID)
		}
		ca, err := newMintingCAFromPEM(active.CertPEM, keyPEM, m.cfg.LeafValidity)
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("load active CA: %w", err)
		}
		certPEM, leafKeyPEM, err := issueOrReuseNodeCert(
			m.cfg.Dir, ca, m.cfg.NodeCommonName, m.cfg.Organization,
			m.cfg.DNSNames, m.cfg.IPAddrs, m.cfg.LeafValidity, m.cfg.SafetyMargin,
		)
		if err != nil {
			return tls.Certificate{}, nil, err
		}
		leaf, err := x509KeyPair(certPEM, leafKeyPEM)
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("parse node leaf: %w", err)
		}
		return leaf, []tls.Certificate{leaf}, nil
	default:
		return tls.Certificate{}, nil, fmt.Errorf("unsupported PKI mode %q", active.PKIMode)
	}
}

func (m *Manager) selfSignedLeaf(key *TLSKey) (tls.Certificate, error) {
	keyPEM, err := m.unseal(key.KeyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509KeyPair(key.CertPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse self-signed key %q: %w", key.ID, err)
	}
	if len(leaf.Certificate) > 0 {
		if parsed, parseErr := x509.ParseCertificate(leaf.Certificate[0]); parseErr == nil {
			leaf.Leaf = parsed
		}
	}
	return leaf, nil
}

func (m *Manager) unseal(stored string) ([]byte, error) {
	if stored == "" {
		return nil, nil
	}
	if m.cfg.Sealer == nil {
		return []byte(stored), nil
	}
	plain, err := m.cfg.Sealer.OpenString(stored)
	if err != nil {
		return nil, fmt.Errorf("unseal keyring private key: %w", err)
	}
	return []byte(plain), nil
}

// CurrentKeyring returns a copy of the current keyring.
func (m *Manager) CurrentKeyring() *TLSKeyring {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current.Clone()
}

// DropBootstrapTrust removes the bootstrap CA from the trusted pool.
func (m *Manager) DropBootstrapTrust() {
	m.mu.Lock()
	m.bootstrap = nil
	m.dropped = true
	current := m.current.Clone()
	m.mu.Unlock()
	if current != nil {
		if err := m.applyKeyring(current); err != nil {
			m.cfg.Logger.Warn("drop bootstrap trust: reapply keyring failed", map[string]any{"error": err.Error()})
		}
	}
}
