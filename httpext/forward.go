package httpext

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/disaster37/raft/transport"
)

const (
	defaultForwardDialTimeout           = 10 * time.Second
	defaultForwardResponseHeaderTimeout = 30 * time.Second
	defaultForwardIdleConnTimeout       = 90 * time.Second
	defaultForwardTLSHandshakeTimeout   = 10 * time.Second
)

// DefaultForwardHeader is the default loop-prevention header name.
const DefaultForwardHeader = "X-Raft-Leader-Forwarded"

// ErrNoLeader is returned by Forwarder when no Raft leader is known.
var ErrNoLeader = errors.New("httpext: no leader available")

// ErrInvalidLeaderAddr is returned by Forwarder when the leader address cannot
// be parsed into host:port.
var ErrInvalidLeaderAddr = errors.New("httpext: invalid leader address")

var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// LeaderForwardConfig configures LeaderForwardMiddleware and Forwarder.
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

// ForwardRequest describes an incoming HTTP request to be forwarded to the
// current Raft leader in a framework-agnostic manner.
type ForwardRequest struct {
	Method     string
	RequestURI string
	Header     http.Header
	Body       io.Reader
}

// ForwardResponse is the leader's HTTP response returned by Forwarder.Forward.
// Callers must close Body when non-nil.
type ForwardResponse struct {
	StatusCode int
	Header     http.Header
	Body       io.ReadCloser
}

// Forwarder encapsulates leader-forwarding policy, target derivation, loop
// prevention, hop-by-hop header stripping, and a pooled mTLS *http.Client that
// hot-reloads certificates on every dial via DynamicTLSProvider.DialTLSConfig.
type Forwarder struct {
	cfg        LeaderForwardConfig
	headerName string
	scheme     string
	client     *http.Client
}

// NewForwarder constructs a concurrency-safe Forwarder.
func NewForwarder(cfg LeaderForwardConfig) *Forwarder {
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = DefaultForwardHeader
	}
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return &Forwarder{
		cfg:        cfg,
		headerName: headerName,
		scheme:     scheme,
		client:     NewForwardHTTPClient(cfg),
	}
}

// NewForwardHTTPClient constructs a concurrency-safe *http.Client with
// connection pooling and per-dial dynamic mTLS via cfg.TLSProvider.
func NewForwardHTTPClient(cfg LeaderForwardConfig) *http.Client {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}
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

// Client returns the underlying pooled *http.Client.
func (f *Forwarder) Client() *http.Client { return f.client }

// HeaderName returns the loop-prevention header name.
func (f *Forwarder) HeaderName() string { return f.headerName }

// Scheme returns the target URL scheme ("https" or "http").
func (f *Forwarder) Scheme() string { return f.scheme }

// ShouldForward reports whether a request with (method, path) and the given
// value of the loop-prevention header should be forwarded to the leader.
func (f *Forwarder) ShouldForward(method, path, forwardHeaderValue string) bool {
	if forwardHeaderValue != "" {
		return false
	}
	if f.cfg.LeaderInfo == nil || f.cfg.LeaderInfo.IsLeader() {
		return false
	}
	if f.cfg.PinnedRouteFn != nil {
		return f.cfg.PinnedRouteFn(method, path)
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// Target derives the (scheme, host:port) of the current leader's HTTP server.
func (f *Forwarder) Target() (scheme, hostPort string, err error) {
	if f.cfg.LeaderInfo == nil {
		return "", "", ErrNoLeader
	}
	leaderAddr := f.cfg.LeaderInfo.LeaderAddress()
	if leaderAddr == "" {
		return "", "", ErrNoLeader
	}
	host, port, err := net.SplitHostPort(leaderAddr)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidLeaderAddr, err)
	}
	if f.cfg.TargetPort > 0 {
		port = strconv.Itoa(f.cfg.TargetPort)
	}
	return f.scheme, net.JoinHostPort(host, port), nil
}

// TargetURL builds the full leader URL for requestURI (e.g.
// "/api/v1/traces?x=1").
func (f *Forwarder) TargetURL(requestURI string) (string, error) {
	scheme, hostPort, err := f.Target()
	if err != nil {
		return "", err
	}
	return buildTargetURL(scheme, hostPort, requestURI), nil
}

// Forward executes req against the current Raft leader, setting the
// loop-prevention header and stripping hop-by-hop headers.
func (f *Forwarder) Forward(ctx context.Context, req *ForwardRequest) (*ForwardResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("httpext: nil forward request")
	}
	scheme, hostPort, err := f.Target()
	if err != nil {
		return nil, err
	}
	//nolint:gosec // the target is the trusted cluster leader address
	outReq, err := http.NewRequestWithContext(ctx, req.Method, buildTargetURL(scheme, hostPort, req.RequestURI), req.Body)
	if err != nil {
		return nil, fmt.Errorf("create forwarded request: %w", err)
	}
	if req.Header != nil {
		outReq.Header = req.Header.Clone()
	}
	outReq.Header.Set(f.headerName, "1")
	outReq.Host = hostPort
	removeHopByHop(outReq.Header)

	//nolint:gosec,bodyclose // trusted leader target; caller owns resp.Body
	resp, err := f.client.Do(outReq)
	if err != nil {
		return nil, fmt.Errorf("forward request: %w", err)
	}
	return &ForwardResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       resp.Body,
	}, nil
}

// HopByHopHeaders returns a copy of the standard HTTP hop-by-hop header names.
func HopByHopHeaders() []string {
	return append([]string(nil), hopByHopHeaders...)
}

// IsHopByHopHeader reports whether name (case-insensitive) is a hop-by-hop
// header.
func IsHopByHopHeader(name string) bool {
	for _, header := range hopByHopHeaders {
		if strings.EqualFold(name, header) {
			return true
		}
	}
	return false
}

// StripForwardMarker removes the loop-prevention header from incoming
// requests.
func StripForwardMarker(headerName string) func(http.Handler) http.Handler {
	if headerName == "" {
		headerName = DefaultForwardHeader
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
	fwd := NewForwarder(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !fwd.ShouldForward(r.Method, r.URL.Path, r.Header.Get(fwd.HeaderName())) {
				r.Header.Del(fwd.HeaderName())
				next.ServeHTTP(w, r)
				return
			}
			resp, err := fwd.Forward(r.Context(), &ForwardRequest{
				Method:     r.Method,
				RequestURI: r.URL.RequestURI(),
				Header:     r.Header,
				Body:       r.Body,
			})
			if err != nil {
				switch {
				case errors.Is(err, ErrNoLeader):
					http.Error(w, "no leader available", http.StatusServiceUnavailable)
				case errors.Is(err, ErrInvalidLeaderAddr):
					http.Error(w, "invalid leader address", http.StatusBadGateway)
				default:
					http.Error(w, "leader proxy failed", http.StatusBadGateway)
				}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			for k, values := range resp.Header {
				for _, v := range values {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
		})
	}
}

func buildTargetURL(scheme, hostPort, requestURI string) string {
	return fmt.Sprintf("%s://%s%s", scheme, hostPort, requestURI)
}

func removeHopByHop(h http.Header) {
	for _, token := range strings.Split(h.Get("Connection"), ",") {
		if name := strings.TrimSpace(token); name != "" {
			h.Del(name)
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}
