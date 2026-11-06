// Package keyring implements the replicated TLS keyring and Vault-style
// two-phase key rotation.
package keyring

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/pki"
	"github.com/disaster37/raft/storage"
)

var (
	newMintingCA         = pki.NewMintingCA
	newMintingCAWithSANs = pki.NewMintingCAWithSANs
	parsePEMCert         = pki.ParsePEMCert
	newKeyID             = randomKeyID
)

// TLSKey represents a single cryptographic key/CA entry in the replicated
// keyring.
type TLSKey struct {
	ID           string    `json:"id"`
	PKIMode      string    `json:"pki_mode"`
	CertPEM      []byte    `json:"cert_pem"`
	KeyPEM       string    `json:"key_pem"`
	CreatedTime  time.Time `json:"created_time"`
	NotAfter     time.Time `json:"not_after"`
	AppliedIndex uint64    `json:"applied_index"`
	IsCA         bool      `json:"is_ca"`
}

// TLSKeyring is the replicated set of TLS keys stored in the Raft FSM.
type TLSKeyring struct {
	Keys         []*TLSKey `json:"keys"`
	ActiveKeyID  string    `json:"active_key_id"`
	Term         uint64    `json:"term"`
	AppliedIndex uint64    `json:"applied_index"`
}

// GetActive returns the active key, or nil.
func (k *TLSKeyring) GetActive() *TLSKey {
	if k == nil {
		return nil
	}
	for _, key := range k.Keys {
		if key != nil && key.ID == k.ActiveKeyID {
			return key
		}
	}
	return nil
}

// Clone returns a deep copy of the keyring.
func (k *TLSKeyring) Clone() *TLSKeyring {
	if k == nil {
		return nil
	}
	out := &TLSKeyring{ActiveKeyID: k.ActiveKeyID, Term: k.Term, AppliedIndex: k.AppliedIndex}
	out.Keys = make([]*TLSKey, 0, len(k.Keys))
	for _, key := range k.Keys {
		if key == nil {
			continue
		}
		copied := *key
		copied.CertPEM = append([]byte(nil), key.CertPEM...)
		out.Keys = append(out.Keys, &copied)
	}
	return out
}

// Validate checks the keyring invariants.
func (k *TLSKeyring) Validate() error {
	if k == nil {
		return fmt.Errorf("keyring is nil")
	}
	if len(k.Keys) == 0 {
		return fmt.Errorf("keyring has no keys")
	}
	if len(k.Keys) > 2 {
		return fmt.Errorf("keyring has %d keys, maximum is 2", len(k.Keys))
	}
	if k.Term == 0 {
		return fmt.Errorf("keyring term must be >= 1")
	}
	foundActive := false
	for _, key := range k.Keys {
		if key == nil {
			return fmt.Errorf("keyring contains a nil key")
		}
		if key.ID == "" {
			return fmt.Errorf("keyring key has an empty ID")
		}
		if len(key.CertPEM) == 0 {
			return fmt.Errorf("keyring key %q has no certificate", key.ID)
		}
		if key.PKIMode != string(config.PKIModeSharedCA) && key.PKIMode != string(config.PKIModeSelfSigned) {
			return fmt.Errorf("keyring key %q has invalid pki_mode %q", key.ID, key.PKIMode)
		}
		if key.ID == k.ActiveKeyID {
			foundActive = true
		}
	}
	if !foundActive {
		return fmt.Errorf("active key %q is not present in the keyring", k.ActiveKeyID)
	}
	return nil
}

// GenerateTLSKeyWithGoca generates a new TLSKey using goca.
func GenerateTLSKeyWithGoca(mode config.PKIMode, commonName, organization string, dnsNames []string, ipAddrs []net.IP, validity time.Duration, sealer storage.Sealer, now time.Time) (*TLSKey, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if commonName == "" {
		commonName = "raft-key"
	}
	if organization == "" {
		organization = "raft"
	}
	var (
		certPEM  []byte
		keyPEM   []byte
		notAfter time.Time
	)
	switch mode {
	case config.PKIModeSharedCA:
		ca, err := newMintingCA(commonName, organization, validity)
		if err != nil {
			return nil, fmt.Errorf("generate shared CA key: %w", err)
		}
		certPEM, keyPEM, err = ca.EncodePEM()
		if err != nil {
			return nil, fmt.Errorf("encode shared CA key: %w", err)
		}
		notAfter = ca.CACertificate().NotAfter
	case config.PKIModeSelfSigned:
		ca, err := newMintingCAWithSANs(commonName, organization, dnsNames, ipAddrs, validity)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed key: %w", err)
		}
		certPEM, keyPEM, err = ca.EncodePEM()
		if err != nil {
			return nil, fmt.Errorf("encode self-signed key: %w", err)
		}
		notAfter = ca.CACertificate().NotAfter
	default:
		return nil, fmt.Errorf("unsupported PKI mode %q", mode)
	}
	storedKey := string(keyPEM)
	if sealer != nil {
		sealed, err := sealer.SealString(string(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("seal keyring private key: %w", err)
		}
		storedKey = sealed
	}
	id, err := newKeyID()
	if err != nil {
		return nil, err
	}
	return &TLSKey{
		ID:          id,
		PKIMode:     string(mode),
		CertPEM:     certPEM,
		KeyPEM:      storedKey,
		CreatedTime: now,
		NotAfter:    notAfter,
		IsCA:        true,
	}, nil
}

// KeyringFromBootstrapCA seeds the initial Term=1 TLSKeyring from the
// bootstrap CA.
func KeyringFromBootstrapCA(mode config.PKIMode, mat *pki.BootstrapMaterial, sealer storage.Sealer, now time.Time) (*TLSKeyring, error) {
	if mat == nil || len(mat.CACertPEM) == 0 {
		return nil, fmt.Errorf("bootstrap material has no CA certificate")
	}
	if now.IsZero() {
		now = time.Now()
	}
	cert, err := parsePEMCert(mat.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse bootstrap CA: %w", err)
	}
	storedKey := string(mat.CAKeyPEM)
	if sealer != nil && storedKey != "" {
		sealed, err := sealer.SealString(storedKey)
		if err != nil {
			return nil, fmt.Errorf("seal bootstrap CA key: %w", err)
		}
		storedKey = sealed
	}
	id, err := newKeyID()
	if err != nil {
		return nil, err
	}
	key := &TLSKey{
		ID:          id,
		PKIMode:     string(mode),
		CertPEM:     append([]byte(nil), mat.CACertPEM...),
		KeyPEM:      storedKey,
		CreatedTime: now,
		NotAfter:    cert.NotAfter,
		IsCA:        true,
	}
	return &TLSKeyring{Keys: []*TLSKey{key}, ActiveKeyID: id, Term: 1}, nil
}

func randomKeyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate key id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("raft-key-%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	), nil
}

// ParseCert parses a key's certificate.
func (k *TLSKey) ParseCert() (*x509.Certificate, error) {
	return parsePEMCert(k.CertPEM)
}
