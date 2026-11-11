package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/go-raft/internal/netutil"
	"github.com/disaster37/go-raft/observ"
)

// IdleCloser is implemented by stream layers that can force pooled
// connections to reconnect (used when the active keyring key changes).
type IdleCloser interface {
	CloseIdleConnections()
}

// trackedConn removes itself from its stream layer's connection map when
// closed, preventing unbounded growth of the tracking map (CWE-400).
type trackedConn struct {
	net.Conn
	closeOnce sync.Once
	onClose   func()
}

func (c *trackedConn) Close() error {
	c.closeOnce.Do(c.onClose)
	return c.Conn.Close()
}

// PlainStreamLayer is a plaintext TCP Raft stream layer.
type PlainStreamLayer struct {
	listener  net.Listener
	advertise net.Addr
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
}

var _ hraft.StreamLayer = (*PlainStreamLayer)(nil)

// NewPlainStreamLayer binds a plaintext listener on bindAddr.
func NewPlainStreamLayer(bindAddr string, advertise net.Addr) (hraft.StreamLayer, error) {
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", bindAddr, err)
	}
	return newPlainStreamLayerFromListener(ln, advertise), nil
}

func newPlainStreamLayerFromListener(ln net.Listener, advertise net.Addr) *PlainStreamLayer {
	if advertise == nil {
		advertise = ln.Addr()
	}
	return &PlainStreamLayer{listener: ln, advertise: advertise, conns: map[net.Conn]struct{}{}}
}

func (l *PlainStreamLayer) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.track(conn), nil
}

func (l *PlainStreamLayer) Dial(addr hraft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", string(addr), timeout)
	if err != nil {
		return nil, err
	}
	return l.track(conn), nil
}

func (l *PlainStreamLayer) Close() error {
	l.CloseIdleConnections()
	return l.listener.Close()
}

func (l *PlainStreamLayer) Addr() net.Addr { return l.advertise }

// CloseIdleConnections closes every tracked connection. Connections are
// closed outside the lock because trackedConn.Close calls untrack.
func (l *PlainStreamLayer) CloseIdleConnections() {
	l.mu.Lock()
	conns := make([]net.Conn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.conns = map[net.Conn]struct{}{}
	l.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (l *PlainStreamLayer) track(conn net.Conn) net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	tracked := &trackedConn{Conn: conn}
	tracked.onClose = func() { l.untrack(tracked) }
	l.conns[tracked] = struct{}{}
	return tracked
}

func (l *PlainStreamLayer) untrack(conn net.Conn) {
	l.mu.Lock()
	delete(l.conns, conn)
	l.mu.Unlock()
}

// TLSStreamLayer is an mTLS Raft stream layer backed by a DynamicTLSProvider.
type TLSStreamLayer struct {
	listener  net.Listener
	provider  *DynamicTLSProvider
	advertise net.Addr
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
}

var _ hraft.StreamLayer = (*TLSStreamLayer)(nil)

// NewTLSStreamLayer binds a TLS listener on bindAddr.
func NewTLSStreamLayer(bindAddr string, advertise net.Addr, provider *DynamicTLSProvider) (hraft.StreamLayer, error) {
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", bindAddr, err)
	}
	return newTLSStreamLayerFromListener(ln, advertise, provider), nil
}

func newTLSStreamLayerFromListener(ln net.Listener, advertise net.Addr, provider *DynamicTLSProvider) *TLSStreamLayer {
	if advertise == nil {
		advertise = ln.Addr()
	}
	return &TLSStreamLayer{listener: ln, provider: provider, advertise: advertise, conns: map[net.Conn]struct{}{}}
}

func (l *TLSStreamLayer) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Server(conn, l.provider.ServerTLSConfig())
	return l.track(tlsConn), nil
}

func (l *TLSStreamLayer) Dial(addr hraft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	host, _, err := net.SplitHostPort(string(addr))
	if err != nil {
		return nil, fmt.Errorf("parse dial addr %q: %w", addr, err)
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", string(addr), l.provider.DialTLSConfig(host))
	if err != nil {
		return nil, err
	}
	return l.track(conn), nil
}

func (l *TLSStreamLayer) Close() error {
	l.CloseIdleConnections()
	return l.listener.Close()
}

func (l *TLSStreamLayer) Addr() net.Addr { return l.advertise }

// CloseIdleConnections closes every tracked connection. Connections are
// closed outside the lock because trackedConn.Close calls untrack.
func (l *TLSStreamLayer) CloseIdleConnections() {
	l.mu.Lock()
	conns := make([]net.Conn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.conns = map[net.Conn]struct{}{}
	l.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (l *TLSStreamLayer) track(conn net.Conn) net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	tracked := &trackedConn{Conn: conn}
	tracked.onClose = func() { l.untrack(tracked) }
	l.conns[tracked] = struct{}{}
	return tracked
}

func (l *TLSStreamLayer) untrack(conn net.Conn) {
	l.mu.Lock()
	delete(l.conns, conn)
	l.mu.Unlock()
}

// RetryingStreamLayer re-resolves DNS before every dial and retries on
// ECONNREFUSED, which is the symptom of a stale DNS cache after a pod
// restart.
type RetryingStreamLayer struct {
	inner        hraft.StreamLayer
	provider     *DynamicTLSProvider
	dialTimeout  time.Duration
	maxRetries   int
	retryBackoff time.Duration
	metrics      observ.MetricsCollector
	mu           sync.Mutex
	conns        map[net.Conn]struct{}
}

var _ hraft.StreamLayer = (*RetryingStreamLayer)(nil)

// NewRetryingStreamLayer wraps inner with DNS re-resolution and retry logic.
func NewRetryingStreamLayer(inner hraft.StreamLayer, provider *DynamicTLSProvider, dialTimeout time.Duration, maxRetries int, retryBackoff time.Duration, metrics observ.MetricsCollector) hraft.StreamLayer {
	if metrics == nil {
		metrics = observ.NewNoopMetrics()
	}
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	if retryBackoff <= 0 {
		retryBackoff = 500 * time.Millisecond
	}
	return &RetryingStreamLayer{
		inner:        inner,
		provider:     provider,
		dialTimeout:  dialTimeout,
		maxRetries:   maxRetries,
		retryBackoff: retryBackoff,
		metrics:      metrics,
		conns:        map[net.Conn]struct{}{},
	}
}

func (l *RetryingStreamLayer) Dial(addr hraft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(string(addr))
	if err != nil {
		return nil, fmt.Errorf("parse dial addr %q: %w", addr, err)
	}
	if timeout <= 0 {
		timeout = l.dialTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	var lastErr error
	for attempt := 0; attempt <= l.maxRetries; attempt++ {
		if attempt > 0 {
			l.metrics.IncDialRetries()
			time.Sleep(l.retryBackoff * time.Duration(attempt))
		}
		// Bound DNS resolution by the dial timeout so a hung resolver cannot
		// stall the Raft transport indefinitely (CWE-400).
		resolveCtx, cancel := context.WithTimeout(context.Background(), timeout)
		ips, resolveErr := net.DefaultResolver.LookupHost(resolveCtx, host)
		cancel()
		if resolveErr != nil {
			l.metrics.IncDNSResolutionFailures()
			lastErr = fmt.Errorf("resolve %s: %w", host, resolveErr)
			continue
		}
		if len(ips) == 0 {
			l.metrics.IncDNSResolutionFailures()
			lastErr = fmt.Errorf("resolve %s: no addresses", host)
			continue
		}
		for _, ip := range ips {
			target := net.JoinHostPort(ip, port)
			var conn net.Conn
			var dialErr error
			if l.provider != nil {
				conn, dialErr = tls.DialWithDialer(dialer, "tcp", target, l.provider.DialTLSConfig(host))
			} else {
				conn, dialErr = dialer.Dial("tcp", target)
			}
			if dialErr == nil {
				return l.track(conn), nil
			}
			lastErr = dialErr
			if !netutil.IsConnRefused(dialErr) {
				return nil, dialErr
			}
		}
	}
	return nil, fmt.Errorf("dial %s: %w (retries exhausted)", addr, lastErr)
}

func (l *RetryingStreamLayer) Accept() (net.Conn, error) { return l.inner.Accept() }
func (l *RetryingStreamLayer) Close() error {
	l.CloseIdleConnections()
	return l.inner.Close()
}
func (l *RetryingStreamLayer) Addr() net.Addr { return l.inner.Addr() }

// CloseIdleConnections closes every tracked connection and cascades to the
// inner stream layer so accepted server-side connections are also closed.
func (l *RetryingStreamLayer) CloseIdleConnections() {
	l.mu.Lock()
	conns := make([]net.Conn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.conns = map[net.Conn]struct{}{}
	l.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	if inner, ok := l.inner.(IdleCloser); ok {
		inner.CloseIdleConnections()
	}
}

func (l *RetryingStreamLayer) track(conn net.Conn) net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	tracked := &trackedConn{Conn: conn}
	tracked.onClose = func() { l.untrack(tracked) }
	l.conns[tracked] = struct{}{}
	return tracked
}

func (l *RetryingStreamLayer) untrack(conn net.Conn) {
	l.mu.Lock()
	delete(l.conns, conn)
	l.mu.Unlock()
}

// EchoMagic is the 4-byte prefix used to multiplex follower echo connections
// on the Raft listener.
var EchoMagic = []byte("ECHO")

const echoMagicLen = 4

// muxListener peeks the first four bytes of each accepted connection. Echo
// connections are handed to handler; all other connections are returned to
// the Raft stream layer with the peeked bytes replayed. Echo handlers are
// bounded by sem so a peer cannot spawn unbounded goroutines, and peekTimeout
// bounds how long a slow-loris connection can stall Accept.
type muxListener struct {
	listener    net.Listener
	handler     func(net.Conn)
	sem         chan struct{}
	peekTimeout time.Duration
}

func (l *muxListener) Accept() (net.Conn, error) {
	peekTimeout := l.peekTimeout
	if peekTimeout <= 0 {
		peekTimeout = defaultEchoPeekTimeout
	}
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(peekTimeout))
		var buf [echoMagicLen]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			_ = conn.Close()
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})
		if bytes.Equal(buf[:], EchoMagic) {
			if l.sem == nil {
				go l.handler(conn)
				continue
			}
			select {
			case l.sem <- struct{}{}:
				go func() {
					defer func() { <-l.sem }()
					l.handler(conn)
				}()
			default:
				_ = conn.Close()
			}
			continue
		}
		return &prefixConn{Conn: conn, prefix: buf[:]}, nil
	}
}

func (l *muxListener) Close() error   { return l.listener.Close() }
func (l *muxListener) Addr() net.Addr { return l.listener.Addr() }

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
