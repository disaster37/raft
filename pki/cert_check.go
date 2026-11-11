package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/disaster37/raft/internal/fileutil"
)

// IssueOrReuseNodeCert issues a per-node leaf certificate signed by ca and
// persists it at <dir>/node.crt and <dir>/node.key (0600). A persisted pair is
// reused only when it is still valid, signed by the current CA, has the
// expected CN, and covers the required SANs.
func IssueOrReuseNodeCert(dir string, ca *MintingCA, commonName, organization string, dnsNames []string, ipAddrs []net.IP, validity, safetyMargin time.Duration) (certPEM, keyPEM []byte, err error) {
	if ca == nil {
		return nil, nil, fmt.Errorf("issue node cert: nil CA")
	}
	if err := fileutil.EnsureDir0700(dir); err != nil {
		return nil, nil, err
	}
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")

	//nolint:gosec // certPath is a fixed file under the configured TLS dir
	if existingCert, readErr := os.ReadFile(certPath); readErr == nil { // #nosec G304
		//nolint:gosec // keyPath is a fixed file under the configured TLS dir
		if existingKey, keyErr := os.ReadFile(keyPath); keyErr == nil { // #nosec G304
			if cert, parseErr := ParsePEMCert(existingCert); parseErr == nil &&
				ReusableNodeCert(cert, ca, commonName, dnsNames, ipAddrs, safetyMargin, time.Now()) {
				return existingCert, existingKey, nil
			}
		}
	}

	certPEM, keyPEM, err = ca.IssuePeerCertificate(commonName, organization, dnsNames, ipAddrs, validity)
	if err != nil {
		return nil, nil, fmt.Errorf("issue node cert: %w", err)
	}
	if err := fileutil.WriteFile0600(certPath, certPEM); err != nil {
		return nil, nil, err
	}
	if err := fileutil.WriteFile0600(keyPath, keyPEM); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// ReusableNodeCert reports whether cert may be reused as this node's leaf.
func ReusableNodeCert(cert *x509.Certificate, ca *MintingCA, commonName string, dnsNames []string, ipAddrs []net.IP, safetyMargin time.Duration, now time.Time) bool {
	if cert == nil || ca == nil {
		return false
	}
	if safetyMargin <= 0 {
		safetyMargin = DefaultSafetyMargin
	}
	if cert.NotBefore.After(now) || !cert.NotAfter.After(now.Add(safetyMargin)) {
		return false
	}
	caCert := ca.CACertificate()
	if caCert == nil || cert.CheckSignatureFrom(caCert) != nil {
		return false
	}
	if cert.Subject.CommonName != commonName {
		return false
	}
	return CoversSANs(cert, dnsNames, ipAddrs)
}

// CoversSANs reports whether cert's SANs cover every required DNS name and IP
// address. Extra SANs are allowed.
func CoversSANs(cert *x509.Certificate, dnsNames []string, ipAddrs []net.IP) bool {
	if cert == nil {
		return false
	}
	haveDNS := make(map[string]struct{}, len(cert.DNSNames))
	for _, n := range cert.DNSNames {
		haveDNS[n] = struct{}{}
	}
	for _, n := range dnsNames {
		if _, ok := haveDNS[n]; !ok {
			return false
		}
	}
	for _, want := range NormalizeIPs(ipAddrs) {
		found := false
		for _, have := range cert.IPAddresses {
			if have.Equal(want) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// NormalizeIPs deduplicates and canonicalizes an IP slice.
func NormalizeIPs(in []net.IP) []net.IP {
	out := make([]net.IP, 0, len(in))
	for _, ip := range in {
		if ip == nil {
			continue
		}
		dup := false
		for _, existing := range out {
			if existing.Equal(ip) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, ip)
		}
	}
	return out
}

// ParsePEMCert parses the first CERTIFICATE PEM block.
func ParsePEMCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("parse PEM cert: no block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PEM cert: %w", err)
	}
	return cert, nil
}
