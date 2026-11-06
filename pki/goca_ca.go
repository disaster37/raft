// Package pki wraps github.com/disaster37/goca for CA creation, leaf
// issuance, certificate reuse, and pre-Raft bootstrap material.
package pki

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	"github.com/disaster37/goca"
)

// DefaultSafetyMargin is the default re-issue window before expiry.
const DefaultSafetyMargin = 7 * 24 * time.Hour

const (
	defaultCAValidityDays = 3650
	maxValidityDays       = 3650
	backdate              = 5 * time.Minute
)

// MintingCA wraps a goca CA for root CA creation and leaf issuance.
type MintingCA struct {
	gocaCA        *goca.CA
	clientCertTTL time.Duration
}

// NewMintingCA creates a new self-signed CA via goca.
func NewMintingCA(commonName, organization string, validity time.Duration) (*MintingCA, error) {
	if commonName == "" {
		commonName = "raft-ca"
	}
	if organization == "" {
		organization = "raft"
	}
	days := validityDays(validity, defaultCAValidityDays)
	ca, err := goca.New(commonName, goca.Identity{
		Organization:       organization,
		OrganizationalUnit: "engineering",
		Country:            "US",
		Locality:           "San Francisco",
		Province:           "California",
		Valid:              days,
	})
	if err != nil {
		return nil, fmt.Errorf("create minting CA: %w", err)
	}
	return &MintingCA{gocaCA: ca}, nil
}

// NewMintingCAWithSANs creates a self-signed CA/leaf hybrid certificate with
// the supplied DNS and IP SANs. It is used for Vault-compatible self-signed
// keyring keys.
func NewMintingCAWithSANs(commonName, organization string, dnsNames []string, ipAddrs []net.IP, validity time.Duration) (*MintingCA, error) {
	if commonName == "" {
		commonName = "raft-key"
	}
	if organization == "" {
		organization = "raft"
	}
	days := validityDays(validity, defaultCAValidityDays)
	ca, err := goca.New(commonName, goca.Identity{
		Organization:       organization,
		OrganizationalUnit: "engineering",
		Country:            "US",
		Locality:           "San Francisco",
		Province:           "California",
		Valid:              days,
		DNSNames:           dnsNames,
		IPAddresses:        ipAddrs,
	})
	if err != nil {
		return nil, fmt.Errorf("create self-signed CA: %w", err)
	}
	return &MintingCA{gocaCA: ca}, nil
}

// NewMintingCAFromPEM loads an existing CA from PEM-encoded certificate and
// private key, repairing a PKCS#1 key stored under a PKCS#8 header.
func NewMintingCAFromPEM(certPEM, keyPEM []byte, clientCertTTL time.Duration) (*MintingCA, error) {
	ca := &goca.CA{}
	if err := ca.LoadCAFromPEM(certPEM, keyPEM); err != nil {
		fixedKey, fixErr := FixPKCS1KeyWithWrongHeader(keyPEM)
		if fixErr != nil {
			return nil, fmt.Errorf("load minting CA from PEM: %w", err)
		}
		if retryErr := ca.LoadCAFromPEM(certPEM, fixedKey); retryErr != nil {
			return nil, fmt.Errorf("load minting CA from PEM: %w", retryErr)
		}
	}
	return &MintingCA{gocaCA: ca, clientCertTTL: clientCertTTL}, nil
}

// FixPKCS1KeyWithWrongHeader detects PKCS#1 RSA key bytes stored under a
// "PRIVATE KEY" (PKCS#8) PEM header and re-encodes them as "RSA PRIVATE KEY".
func FixPKCS1KeyWithWrongHeader(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("decode key PEM: no block found")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("key PEM type is %q, not PKCS#8", block.Type)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return nil, fmt.Errorf("key is valid PKCS#8")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("key is neither PKCS#1 nor PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: block.Bytes}), nil
}

// Signer returns the CA private key as a crypto.Signer.
func (ca *MintingCA) Signer() crypto.Signer { return ca.gocaCA.GoSigner() }

// CACertificate returns the parsed CA certificate.
func (ca *MintingCA) CACertificate() *x509.Certificate {
	return ca.gocaCA.GoCertificate()
}

// CertPool returns a pool containing this CA's certificate.
func (ca *MintingCA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.gocaCA.GoCertificate())
	return pool
}

// TLSCertificate returns the CA certificate as a tls.Certificate.
func (ca *MintingCA) TLSCertificate() (tls.Certificate, error) {
	block, _ := pem.Decode([]byte(ca.gocaCA.GetCertificate()))
	if block == nil {
		return tls.Certificate{}, fmt.Errorf("decode CA cert PEM: no block found")
	}
	return tls.Certificate{
		Certificate: [][]byte{block.Bytes},
		PrivateKey:  ca.gocaCA.GoSigner(),
	}, nil
}

// EncodePEM returns the CA certificate and private key as PEM bytes.
func (ca *MintingCA) EncodePEM() (certPEM, keyPEM []byte, err error) {
	return []byte(ca.gocaCA.GetCertificate()), []byte(ca.gocaCA.GetPrivateKey()), nil
}

// IssuePeerCertificate signs an mTLS peer certificate with DNS and IP SANs.
func (ca *MintingCA) IssuePeerCertificate(commonName, organization string, dnsNames []string, ipAddrs []net.IP, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	cert, err := ca.gocaCA.IssueCertificate(commonName, goca.Identity{
		Organization:       organizationOrDefault(organization),
		OrganizationalUnit: "engineering",
		Country:            "US",
		Locality:           "San Francisco",
		Province:           "California",
		Type:               "server-client",
		ValidDuration:      leafValidity(ttl),
		Backdate:           backdate,
		DNSNames:           dnsNames,
		IPAddresses:        ipAddrs,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("issue peer cert: %w", err)
	}
	return []byte(cert.Certificate), []byte(cert.PrivateKey), nil
}

// IssueServerCertificate signs a TLS server certificate with DNS SANs.
func (ca *MintingCA) IssueServerCertificate(commonName, organization string, dnsNames []string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	cert, err := ca.gocaCA.IssueCertificate(commonName, goca.Identity{
		Organization:       organizationOrDefault(organization),
		OrganizationalUnit: "engineering",
		Country:            "US",
		Locality:           "San Francisco",
		Province:           "California",
		Type:               "server",
		ValidDuration:      leafValidity(ttl),
		Backdate:           backdate,
		DNSNames:           dnsNames,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("issue server cert: %w", err)
	}
	return []byte(cert.Certificate), []byte(cert.PrivateKey), nil
}

// IssueClientCertificate signs a TLS client certificate.
func (ca *MintingCA) IssueClientCertificate(commonName, organization string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	cert, err := ca.gocaCA.IssueCertificate(commonName, goca.Identity{
		Organization:       organizationOrDefault(organization),
		OrganizationalUnit: "engineering",
		Country:            "US",
		Locality:           "San Francisco",
		Province:           "California",
		Type:               "client",
		ValidDuration:      leafValidity(ttl),
		Backdate:           backdate,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("issue client cert: %w", err)
	}
	return []byte(cert.Certificate), []byte(cert.PrivateKey), nil
}

func organizationOrDefault(org string) string {
	if org == "" {
		return "raft"
	}
	return org
}

func validityDays(d time.Duration, fallback int) int {
	if d <= 0 {
		return fallback
	}
	days := int(d.Hours() / 24)
	if days < 1 {
		days = 1
	}
	if days > maxValidityDays {
		days = maxValidityDays
	}
	return days
}

func leafValidity(d time.Duration) time.Duration {
	if d <= 0 {
		return 365 * 24 * time.Hour
	}
	max := time.Duration(maxValidityDays) * 24 * time.Hour
	if d > max {
		return max
	}
	return d
}
