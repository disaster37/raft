package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync/atomic"
)

type tlsState struct {
	leaf       tls.Certificate
	rootPool   *x509.CertPool
	clientPool *x509.CertPool
	clientAuth bool
	allLeaves  []tls.Certificate
}

// DynamicTLSProvider atomically manages server/client certificates and
// Root/Client CA pools so leaf and CA rotations take effect without
// restarting listeners.
type DynamicTLSProvider struct {
	state atomic.Pointer[tlsState]
}

// NewDynamicTLSProvider returns a provider with the supplied initial state.
func NewDynamicTLSProvider(leaf tls.Certificate, rootPool, clientPool *x509.CertPool, clientAuth bool) *DynamicTLSProvider {
	p := &DynamicTLSProvider{}
	p.state.Store(&tlsState{
		leaf:       leaf,
		rootPool:   rootPool,
		clientPool: clientPool,
		clientAuth: clientAuth,
		allLeaves:  []tls.Certificate{leaf},
	})
	return p
}

// Update atomically replaces the leaf and CA pools.
func (p *DynamicTLSProvider) Update(leaf tls.Certificate, rootPool, clientPool *x509.CertPool) {
	old := p.state.Load()
	clientAuth := true
	if old != nil {
		clientAuth = old.clientAuth
	}
	p.state.Store(&tlsState{
		leaf:       leaf,
		rootPool:   rootPool,
		clientPool: clientPool,
		clientAuth: clientAuth,
		allLeaves:  []tls.Certificate{leaf},
	})
}

// UpdateKeyringView atomically installs the active leaf, all trusted leaves,
// and the union CA pool used for both server and client verification.
func (p *DynamicTLSProvider) UpdateKeyringView(activeLeaf tls.Certificate, allLeaves []tls.Certificate, trustedCAPool *x509.CertPool) {
	old := p.state.Load()
	clientAuth := true
	if old != nil {
		clientAuth = old.clientAuth
	}
	if len(allLeaves) == 0 {
		allLeaves = []tls.Certificate{activeLeaf}
	}
	p.state.Store(&tlsState{
		leaf:       activeLeaf,
		rootPool:   trustedCAPool,
		clientPool: trustedCAPool,
		clientAuth: clientAuth,
		allLeaves:  allLeaves,
	})
}

// GetCertificate returns the active leaf, or a leaf matching the SNI name.
func (p *DynamicTLSProvider) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	st := p.state.Load()
	if st == nil {
		return nil, fmt.Errorf("tls provider: no certificate loaded")
	}
	if hello != nil && hello.ServerName != "" {
		for i := range st.allLeaves {
			leaf := &st.allLeaves[i]
			// Parse into a local variable rather than mutating the shared
			// tls.Certificate.Leaf field, which would race across concurrent
			// handshakes when a consumer supplies a certificate without Leaf.
			parsed := leaf.Leaf
			if parsed == nil && len(leaf.Certificate) > 0 {
				if p, err := x509.ParseCertificate(leaf.Certificate[0]); err == nil {
					parsed = p
				}
			}
			if parsed != nil {
				for _, name := range parsed.DNSNames {
					if name == hello.ServerName {
						return leaf, nil
					}
				}
			}
		}
	}
	return &st.leaf, nil
}

// GetClientCertificate returns the active client leaf, preferring a leaf
// whose issuer is acceptable to the server.
func (p *DynamicTLSProvider) GetClientCertificate(req *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	st := p.state.Load()
	if st == nil {
		return nil, fmt.Errorf("tls provider: no certificate loaded")
	}
	if req != nil && len(req.AcceptableCAs) > 0 {
		for i := range st.allLeaves {
			leaf := &st.allLeaves[i]
			// Parse into a local variable to avoid mutating shared state.
			parsed := leaf.Leaf
			if parsed == nil && len(leaf.Certificate) > 0 {
				if p, err := x509.ParseCertificate(leaf.Certificate[0]); err == nil {
					parsed = p
				}
			}
			if parsed == nil {
				continue
			}
			for _, ca := range req.AcceptableCAs {
				if string(parsed.RawIssuer) == string(ca) {
					return leaf, nil
				}
			}
		}
	}
	return &st.leaf, nil
}

// GetConfigForClient returns a per-connection server config with the current
// ClientCAs and ClientAuth, so CA rotations apply to new handshakes.
func (p *DynamicTLSProvider) GetConfigForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	st := p.state.Load()
	if st == nil {
		return nil, fmt.Errorf("tls provider: no state loaded")
	}
	clientAuth := tls.NoClientCert
	if st.clientAuth {
		clientAuth = tls.RequireAndVerifyClientCert
	}
	return &tls.Config{
		GetCertificate: p.GetCertificate,
		ClientCAs:      st.clientPool,
		ClientAuth:     clientAuth,
		MinVersion:     tls.VersionTLS12,
	}, nil
}

// ServerTLSConfig returns the server-side tls.Config.
func (p *DynamicTLSProvider) ServerTLSConfig() *tls.Config {
	st := p.state.Load()
	clientAuth := tls.NoClientCert
	if st != nil && st.clientAuth {
		clientAuth = tls.RequireAndVerifyClientCert
	}
	return &tls.Config{
		GetCertificate:     p.GetCertificate,
		GetConfigForClient: p.GetConfigForClient,
		ClientAuth:         clientAuth,
		MinVersion:         tls.VersionTLS12,
	}
}

// DialTLSConfig returns a fresh client config for one outbound dial. The
// RootCAs pool is read from the current state on every call, fixing the
// static-CA bug in earlier implementations.
func (p *DynamicTLSProvider) DialTLSConfig(serverName string) *tls.Config {
	st := p.state.Load()
	cfg := &tls.Config{
		GetClientCertificate: p.GetClientCertificate,
		ServerName:           serverName,
		MinVersion:           tls.VersionTLS12,
	}
	if st != nil {
		cfg.RootCAs = st.rootPool
	}
	return cfg
}

// CurrentCertPool returns the current trusted CA pool.
func (p *DynamicTLSProvider) CurrentCertPool() *x509.CertPool {
	st := p.state.Load()
	if st == nil {
		return nil
	}
	return st.rootPool
}
