package httpext

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/disaster37/raft/transport"
)

const (
	defaultForwardDialTimeout           = 10 * time.Second
	defaultForwardResponseHeaderTimeout = 30 * time.Second
	defaultForwardIdleConnTimeout       = 90 * time.Second
	defaultForwardTLSHandshakeTimeout   = 10 * time.Second
)

// LeaderForwardConfig configures LeaderForwardMiddleware.
type LeaderForwardConfig struct {
	LeaderInfo    LeaderInfo
	TargetPort    int
	Scheme        string
	HeaderName    string
	TLSProvider   *transport.DynamicTLSProvider
	PinnedRouteFn func(method, path string) bool
	// DialTimeout bounds TCP/TLS dialing to the leader. Zero uses 10s.
	DialTimeout time.Duration
	// ResponseHeaderTimeout bounds waiting for the leader's response headers.
	// Zero uses 30s.
	ResponseHeaderTimeout time.Duration
	// IdleConnTimeout bounds how long pooled connections stay idle. Zero uses
	// 90s.
	IdleConnTimeout time.Duration
}

// StripForwardMarker removes the loop-prevention header from incoming
// requests.
func StripForwardMarker(headerName string) func(http.Handler) http.Handler {
	if headerName == "" {
		headerName = "X-Raft-Leader-Forwarded"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Del(headerName)
			next.ServeHTTP(w, r)
		})
	}
}

// LeaderForwardMiddleware forwards mutating requests (and pinned GET routes)
// from followers to the leader over mTLS. The returned middleware owns one
// shared, concurrency-safe HTTP transport so forwarded requests reuse pooled
// connections instead of allocating a transport per request.
func LeaderForwardMiddleware(cfg LeaderForwardConfig) func(http.Handler) http.Handler {
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "X-Raft-Leader-Forwarded"
	}
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}
	client := newForwardClient(cfg, scheme)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(headerName) != "" {
				r.Header.Del(headerName)
				next.ServeHTTP(w, r)
				return
			}
			if cfg.LeaderInfo == nil || cfg.LeaderInfo.IsLeader() {
				next.ServeHTTP(w, r)
				return
			}
			if !shouldForward(cfg, r) {
				next.ServeHTTP(w, r)
				return
			}
			leaderAddr := cfg.LeaderInfo.LeaderAddress()
			if leaderAddr == "" {
				http.Error(w, "no leader available", http.StatusServiceUnavailable)
				return
			}
			targetHost, err := leaderHost(leaderAddr, cfg.TargetPort)
			if err != nil {
				http.Error(w, "invalid leader address", http.StatusBadGateway)
				return
			}
			if err := proxyToLeader(w, r, scheme, targetHost, headerName, client); err != nil {
				http.Error(w, "leader proxy failed", http.StatusBadGateway)
			}
		})
	}
}

func newForwardClient(cfg LeaderForwardConfig, scheme string) *http.Client {
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultForwardDialTimeout
	}
	responseHeaderTimeout := cfg.ResponseHeaderTimeout
	if responseHeaderTimeout <= 0 {
		responseHeaderTimeout = defaultForwardResponseHeaderTimeout
	}
	idleConnTimeout := cfg.IdleConnTimeout
	if idleConnTimeout <= 0 {
		idleConnTimeout = defaultForwardIdleConnTimeout
	}
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   defaultForwardTLSHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
	if scheme == "https" {
		if cfg.TLSProvider != nil {
			tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("split dial address %q: %w", addr, err)
				}
				raw, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(raw, cfg.TLSProvider.DialTLSConfig(host))
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = raw.Close()
					return nil, fmt.Errorf("tls handshake with %s: %w", addr, err)
				}
				return tlsConn, nil
			}
		} else {
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
	}
	return &http.Client{Transport: tr}
}

func shouldForward(cfg LeaderForwardConfig, r *http.Request) bool {
	if cfg.PinnedRouteFn != nil {
		return cfg.PinnedRouteFn(r.Method, r.URL.Path)
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func leaderHost(leaderAddr string, targetPort int) (string, error) {
	host, port, err := net.SplitHostPort(leaderAddr)
	if err != nil {
		return "", fmt.Errorf("split leader address %q: %w", leaderAddr, err)
	}
	if targetPort > 0 {
		port = strconv.Itoa(targetPort)
	}
	return net.JoinHostPort(host, port), nil
}

func proxyToLeader(w http.ResponseWriter, r *http.Request, scheme, targetHost, headerName string, client *http.Client) error {
	url := fmt.Sprintf("%s://%s%s", scheme, targetHost, r.URL.RequestURI())
	//nolint:gosec // the target is the trusted cluster leader address
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, url, r.Body)
	if err != nil {
		return fmt.Errorf("create forwarded request: %w", err)
	}
	outReq.Header = r.Header.Clone()
	outReq.Header.Set(headerName, "1")
	outReq.Host = targetHost
	removeHopByHop(outReq.Header)

	//nolint:gosec // the target is the trusted cluster leader address
	resp, err := client.Do(outReq)
	if err != nil {
		return fmt.Errorf("forward request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	return nil
}

func removeHopByHop(h http.Header) {
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(name)
	}
}
