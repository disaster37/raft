package pki

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/disaster37/raft/internal/fileutil"
)

// BootstrapMaterial holds the initial pre-Raft TLS material.
type BootstrapMaterial struct {
	CACertPEM   []byte
	CAKeyPEM    []byte
	LeafCertPEM []byte
	LeafKeyPEM  []byte
}

// BootstrapProvider resolves the chicken-and-egg TLS bootstrap before Raft
// exists.
type BootstrapProvider interface {
	EnsureBootstrapMaterial(ctx context.Context) (*BootstrapMaterial, error)
}

// FileBootstrapProvider loads CA and leaf material from operator-managed PEM
// files.
type FileBootstrapProvider struct {
	caCertPath string
	certPath   string
	keyPath    string
}

// NewFileBootstrapProvider returns a provider backed by PEM files.
func NewFileBootstrapProvider(caCertPath, certPath, keyPath string) BootstrapProvider {
	return &FileBootstrapProvider{caCertPath: caCertPath, certPath: certPath, keyPath: keyPath}
}

// EnsureBootstrapMaterial reads the configured PEM files.
func (p *FileBootstrapProvider) EnsureBootstrapMaterial(_ context.Context) (*BootstrapMaterial, error) {
	if p.caCertPath == "" || p.certPath == "" || p.keyPath == "" {
		return nil, fmt.Errorf("file bootstrap: ca_cert, cert, and key must all be set")
	}
	caCert, err := os.ReadFile(p.caCertPath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("file bootstrap: read CA cert: %w", err)
	}
	leafCert, err := os.ReadFile(p.certPath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("file bootstrap: read leaf cert: %w", err)
	}
	leafKey, err := os.ReadFile(p.keyPath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("file bootstrap: read leaf key: %w", err)
	}
	return &BootstrapMaterial{CACertPEM: caCert, LeafCertPEM: leafCert, LeafKeyPEM: leafKey}, nil
}

// LocalBootstrapProvider loads or generates a local CA under <dir>/tls. It is
// intended for single-node deployments.
type LocalBootstrapProvider struct {
	dir          string
	caCommonName string
	organization string
	caValidity   time.Duration
}

// NewLocalBootstrapProvider returns a provider that persists a local CA.
func NewLocalBootstrapProvider(dir, caCommonName, organization string, caValidity time.Duration) BootstrapProvider {
	return &LocalBootstrapProvider{dir: dir, caCommonName: caCommonName, organization: organization, caValidity: caValidity}
}

// EnsureBootstrapMaterial loads or creates <dir>/ca.crt and <dir>/ca.key.
func (p *LocalBootstrapProvider) EnsureBootstrapMaterial(_ context.Context) (*BootstrapMaterial, error) {
	if p.dir == "" {
		return nil, fmt.Errorf("local bootstrap: dir is required")
	}
	if err := fileutil.EnsureDir0700(p.dir); err != nil {
		return nil, err
	}
	certPath := filepath.Join(p.dir, "ca.crt")
	keyPath := filepath.Join(p.dir, "ca.key")
	//nolint:gosec // paths come from operator configuration
	if certPEM, err := os.ReadFile(certPath); err == nil { // #nosec G304
		//nolint:gosec // paths come from operator configuration
		if keyPEM, keyErr := os.ReadFile(keyPath); keyErr == nil { // #nosec G304
			return &BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}, nil
		}
	}
	ca, err := NewMintingCA(p.caCommonName, p.organization, p.caValidity)
	if err != nil {
		return nil, err
	}
	certPEM, keyPEM, err := ca.EncodePEM()
	if err != nil {
		return nil, err
	}
	if err := fileutil.WriteFile0600(certPath, certPEM); err != nil {
		return nil, err
	}
	if err := fileutil.WriteFile0600(keyPath, keyPEM); err != nil {
		return nil, err
	}
	return &BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}, nil
}
