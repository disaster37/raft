package keyring

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/disaster37/go-raft/transport"
)

func BenchmarkKeyringSwap(b *testing.B) {
	provider := transport.NewDynamicTLSProvider(tls.Certificate{}, nil, nil, true)
	key, err := GenerateTLSKeyWithGoca("shared-ca", "ca", "org", nil, nil, 0, nil, time.Time{})
	if err != nil {
		b.Fatal(err)
	}
	kr := &TLSKeyring{Keys: []*TLSKey{key}, ActiveKeyID: key.ID, Term: 1}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.UpdateKeyringView(tls.Certificate{}, []tls.Certificate{{}}, provider.CurrentCertPool())
		_ = kr.Clone()
	}
}

func BenchmarkDialTLSConfig(b *testing.B) {
	provider := transport.NewDynamicTLSProvider(tls.Certificate{}, nil, nil, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.DialTLSConfig("localhost")
	}
}
