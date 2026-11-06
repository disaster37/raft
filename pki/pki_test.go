package pki

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"time"

	"github.com/disaster37/goca"
)

func TestMintingCACreateAndReload(t *testing.T) {
	ca, err := NewMintingCA("test-ca", "test-org", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("NewMintingCA: %v", err)
	}
	if ca.CACertificate() == nil || ca.CertPool() == nil {
		t.Fatal("missing CA material")
	}
	if _, err := ca.TLSCertificate(); err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	certPEM, keyPEM, err := ca.EncodePEM()
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}
	reloaded, err := NewMintingCAFromPEM(certPEM, keyPEM, time.Hour)
	if err != nil {
		t.Fatalf("NewMintingCAFromPEM: %v", err)
	}
	if reloaded.CACertificate().Subject.CommonName != "test-ca" {
		t.Fatalf("CN = %q", reloaded.CACertificate().Subject.CommonName)
	}
	if _, _, err := ca.IssueServerCertificate("server", "org", []string{"localhost"}, time.Hour); err != nil {
		t.Fatalf("IssueServerCertificate: %v", err)
	}
	if _, _, err := ca.IssueClientCertificate("client", "org", time.Hour); err != nil {
		t.Fatalf("IssueClientCertificate: %v", err)
	}
	if _, _, err := ca.IssuePeerCertificate("peer", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour); err != nil {
		t.Fatalf("IssuePeerCertificate: %v", err)
	}
}

func TestFixPKCS1KeyWithWrongHeader(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	wrong := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs1})
	fixed, err := FixPKCS1KeyWithWrongHeader(wrong)
	if err != nil {
		t.Fatalf("FixPKCS1KeyWithWrongHeader: %v", err)
	}
	block, _ := pem.Decode(fixed)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("block = %+v", block)
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatalf("parse fixed key: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	valid := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if _, err := FixPKCS1KeyWithWrongHeader(valid); err == nil {
		t.Fatal("expected error for valid PKCS#8")
	}
	if _, err := FixPKCS1KeyWithWrongHeader([]byte("not pem")); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if _, err := FixPKCS1KeyWithWrongHeader(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1})); err == nil {
		t.Fatal("expected error for non-PKCS#8 header")
	}
}

func TestIssueOrReuseNodeCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewMintingCA("ca", "org", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dns := []string{"node-0", "localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	cert1, key1, err := IssueOrReuseNodeCert(dir, ca, "node-0", "org", dns, ips, time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	cert2, key2, err := IssueOrReuseNodeCert(dir, ca, "node-0", "org", dns, ips, time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("reuse: %v", err)
	}
	if string(cert1) != string(cert2) || string(key1) != string(key2) {
		t.Fatal("expected cert reuse")
	}
	info, err := os.Stat(filepath.Join(dir, "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", info.Mode().Perm())
	}

	// Missing SAN forces re-issue.
	cert3, _, err := IssueOrReuseNodeCert(dir, ca, "node-0", "org", append(dns, "extra"), ips, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if string(cert1) == string(cert3) {
		t.Fatal("expected re-issue on missing SAN")
	}

	// Different CA forces re-issue.
	ca2, err := NewMintingCA("ca2", "org", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert4, _, err := IssueOrReuseNodeCert(dir, ca2, "node-0", "org", dns, ips, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if string(cert3) == string(cert4) {
		t.Fatal("expected re-issue on CA change")
	}

	// Near expiry forces re-issue.
	cert5, _, err := IssueOrReuseNodeCert(dir, ca2, "node-0", "org", dns, ips, time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if string(cert4) == string(cert5) {
		t.Fatal("expected re-issue near expiry")
	}
}

func TestCoversSANsAndParse(t *testing.T) {
	ca, err := NewMintingCA("ca", "org", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.IssuePeerCertificate("node", "org", []string{"a", "b"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParsePEMCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !CoversSANs(cert, []string{"a"}, []net.IP{net.ParseIP("127.0.0.1")}) {
		t.Fatal("expected SAN coverage")
	}
	if CoversSANs(cert, []string{"c"}, nil) {
		t.Fatal("unexpected SAN coverage")
	}
	if CoversSANs(nil, nil, nil) {
		t.Fatal("nil cert should not cover")
	}
	if _, err := ParsePEMCert([]byte("bad")); err == nil {
		t.Fatal("expected parse error")
	}
	ips := NormalizeIPs([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.1"), nil})
	if len(ips) != 1 {
		t.Fatalf("ips = %v", ips)
	}
}

func TestBootstrapProviders(t *testing.T) {
	dir := t.TempDir()
	local := NewLocalBootstrapProvider(filepath.Join(dir, "tls"), "ca", "org", 365*24*time.Hour)
	mat, err := local.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatalf("local bootstrap: %v", err)
	}
	if len(mat.CACertPEM) == 0 || len(mat.CAKeyPEM) == 0 {
		t.Fatal("missing local CA material")
	}
	mat2, err := local.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatalf("local bootstrap reload: %v", err)
	}
	if string(mat.CACertPEM) != string(mat2.CACertPEM) {
		t.Fatal("expected CA reuse")
	}
	info, err := os.Stat(filepath.Join(dir, "tls", "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ca key mode = %o", info.Mode().Perm())
	}

	caCertPath := filepath.Join(dir, "tls", "ca.crt")
	leafCertPath := filepath.Join(dir, "tls", "leaf.crt")
	leafKeyPath := filepath.Join(dir, "tls", "leaf.key")
	ca, err := NewMintingCAFromPEM(mat.CACertPEM, mat.CAKeyPEM, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, leafKey, err := ca.IssuePeerCertificate("leaf", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafCertPath, leafCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafKeyPath, leafKey, 0o600); err != nil {
		t.Fatal(err)
	}
	fileProvider := NewFileBootstrapProvider(caCertPath, leafCertPath, leafKeyPath)
	fileMat, err := fileProvider.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatalf("file bootstrap: %v", err)
	}
	if len(fileMat.LeafCertPEM) == 0 || len(fileMat.LeafKeyPEM) == 0 {
		t.Fatal("missing file leaf material")
	}
	bad := NewFileBootstrapProvider("", "", "")
	if _, err := bad.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected error for empty file provider")
	}
}

func TestNewMintingCAWithSANsAndSigner(t *testing.T) {
	ca, err := NewMintingCAWithSANs("shared", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatalf("NewMintingCAWithSANs: %v", err)
	}
	if ca.Signer() == nil {
		t.Fatal("nil signer")
	}
	cert := ca.CACertificate()
	if len(cert.DNSNames) == 0 || len(cert.IPAddresses) == 0 {
		t.Fatalf("missing SANs: %+v", cert)
	}
	if _, err := NewMintingCA("", "", 0); err != nil {
		t.Fatalf("default CA: %v", err)
	}
	if _, err := NewMintingCAWithSANs("", "", nil, nil, 0); err != nil {
		t.Fatalf("default self-signed CA: %v", err)
	}
}

func TestMintingCAErrorPaths(t *testing.T) {
	if _, err := NewMintingCAFromPEM([]byte("bad"), []byte("bad"), time.Hour); err == nil {
		t.Fatal("expected load error")
	}
	ca, _ := NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.EncodePEM()
	if _, err := NewMintingCAFromPEM(certPEM, keyPEM, time.Hour); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, _, err := IssueOrReuseNodeCert(t.TempDir(), nil, "node", "org", nil, nil, time.Hour, time.Minute); err == nil {
		t.Fatal("expected nil CA error")
	}
	if ReusableNodeCert(nil, ca, "node", nil, nil, time.Minute, time.Now()) {
		t.Fatal("nil cert should not be reusable")
	}
	if ReusableNodeCert(ca.CACertificate(), nil, "node", nil, nil, time.Minute, time.Now()) {
		t.Fatal("nil CA should not be reusable")
	}
}

func TestNewMintingCAFromPEMWrongHeader(t *testing.T) {
	ca, err := NewMintingCA("ca", "org", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.EncodePEM()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("decode key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("not RSA")
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)
	wrong := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs1})
	if _, err := NewMintingCAFromPEM(certPEM, wrong, time.Hour); err != nil {
		t.Fatalf("expected PKCS#1 header fix: %v", err)
	}
}

func TestBootstrapProviderErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")
	provider := NewFileBootstrapProvider(missing, missing, missing)
	if _, err := provider.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected file bootstrap error")
	}
	local := NewLocalBootstrapProvider("", "ca", "org", time.Hour)
	if _, err := local.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected local bootstrap error")
	}
	local = NewLocalBootstrapProvider(file, "ca", "org", time.Hour)
	if _, err := local.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected local bootstrap dir error")
	}
}

func TestReusableNodeCertBranches(t *testing.T) {
	ca, _ := NewMintingCA("ca", "org", time.Hour)
	other, _ := NewMintingCA("other", "org", time.Hour)
	certPEM, _, _ := ca.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	cert, _ := ParsePEMCert(certPEM)
	if ReusableNodeCert(cert, other, "node", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Minute, time.Now()) {
		t.Fatal("wrong CA should not be reusable")
	}
	if ReusableNodeCert(cert, ca, "other", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Minute, time.Now()) {
		t.Fatal("wrong CN should not be reusable")
	}
	if ReusableNodeCert(cert, ca, "node", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, time.Now().Add(2*time.Hour)) {
		t.Fatal("future cert should not be reusable")
	}
	if CoversSANs(cert, nil, []net.IP{net.ParseIP("10.0.0.1")}) {
		t.Fatal("missing IP should not be covered")
	}
	if len(NormalizeIPs(nil)) != 0 {
		t.Fatal("expected empty IPs")
	}
}

func TestIssueOrReuseNodeCertDirError(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca, _ := NewMintingCA("ca", "org", time.Hour)
	if _, _, err := IssueOrReuseNodeCert(file, ca, "node", "org", nil, nil, time.Hour, time.Minute); err == nil {
		t.Fatal("expected dir error")
	}
}

func TestIssueCertificatesDefaults(t *testing.T) {
	ca, _ := NewMintingCA("ca", "org", time.Hour)
	if _, _, err := ca.IssuePeerCertificate("peer", "", nil, nil, 0); err != nil {
		t.Fatalf("peer defaults: %v", err)
	}
	if _, _, err := ca.IssueServerCertificate("server", "", nil, 0); err != nil {
		t.Fatalf("server defaults: %v", err)
	}
	if _, _, err := ca.IssueClientCertificate("client", "", 0); err != nil {
		t.Fatalf("client defaults: %v", err)
	}
	if _, _, err := ca.IssuePeerCertificate("peer", "org", nil, nil, 10000*24*time.Hour); err != nil {
		t.Fatalf("peer max ttl: %v", err)
	}
}

func TestLocalBootstrapWriteErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := NewLocalBootstrapProvider(filepath.Join(file, "tls"), "ca", "org", time.Hour)
	if _, err := local.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected local bootstrap write error")
	}
}

func TestMintingCAEmptyErrors(t *testing.T) {
	ca := &MintingCA{gocaCA: &goca.CA{}}
	if _, err := ca.TLSCertificate(); err == nil {
		t.Fatal("expected TLS certificate error")
	}
}
