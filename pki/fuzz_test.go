package pki

import "testing"

func FuzzParsePEMCert(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("not a cert"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePEMCert(data)
	})
}

func FuzzFixPKCS1Key(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("not a key"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = FixPKCS1KeyWithWrongHeader(data)
	})
}
