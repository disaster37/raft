package transport

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hashicorp/go-hclog"
	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/raft/observ"
)

// TransportOptions configures NewStreamTransport.
type TransportOptions struct {
	BindAddr                string
	AdvertiseAddr           string
	AdvertiseResolveTimeout time.Duration
	MaxPool                 int
	Timeout                 time.Duration
	MaxDialRetries          int
	DialRetryBackoff        time.Duration
	TLSProvider             *DynamicTLSProvider
	CustomListener          net.Listener
	LogOutput               io.Writer
	Metrics                 observ.MetricsCollector
	// EchoHandler, when set, receives plaintext connections whose first four
	// bytes are EchoMagic. The handler is responsible for any TLS wrapping.
	EchoHandler func(net.Conn)
	// EchoMaxConcurrent bounds concurrent EchoHandler goroutines. Zero uses
	// 64. Connections beyond the limit are closed immediately.
	EchoMaxConcurrent int
	// EchoPeekTimeout bounds how long the listener waits for the four-byte
	// echo magic before closing a connection. Zero uses 1s.
	EchoPeekTimeout time.Duration
}

const (
	defaultEchoMaxConcurrent = 64
	defaultEchoPeekTimeout   = time.Second
)

// NewStreamTransport binds a Raft transport and returns it together with a
// closer and the advertised address.
func NewStreamTransport(opts TransportOptions) (hraft.Transport, io.Closer, string, error) {
	if opts.MaxPool <= 0 {
		opts.MaxPool = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Metrics == nil {
		opts.Metrics = observ.NewNoopMetrics()
	}

	bindAddr := opts.BindAddr
	if bindAddr == "" && opts.CustomListener != nil {
		bindAddr = opts.CustomListener.Addr().String()
	}
	if bindAddr == "" {
		bindAddr = "127.0.0.1:0"
	}

	advertiseAddr := opts.AdvertiseAddr
	if advertiseAddr == "" {
		advertiseAddr = bindAddr
	}
	if _, err := ResolveAdvertiseAddr(advertiseAddr, opts.AdvertiseResolveTimeout, opts.LogOutput); err != nil {
		return nil, nil, "", fmt.Errorf("resolve advertise addr %s: %w", advertiseAddr, err)
	}
	advertise, err := NewHostAddr(advertiseAddr)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse advertise addr %s: %w", advertiseAddr, err)
	}

	ln := opts.CustomListener
	if ln == nil {
		ln, err = net.Listen("tcp", bindAddr)
		if err != nil {
			return nil, nil, "", fmt.Errorf("listen %s: %w", bindAddr, err)
		}
	}
	if opts.EchoHandler != nil {
		maxConcurrent := opts.EchoMaxConcurrent
		if maxConcurrent <= 0 {
			maxConcurrent = defaultEchoMaxConcurrent
		}
		peekTimeout := opts.EchoPeekTimeout
		if peekTimeout <= 0 {
			peekTimeout = defaultEchoPeekTimeout
		}
		ln = &muxListener{
			listener:    ln,
			handler:     opts.EchoHandler,
			sem:         make(chan struct{}, maxConcurrent),
			peekTimeout: peekTimeout,
		}
	}

	var stream hraft.StreamLayer
	if opts.TLSProvider != nil {
		tlsLayer := newTLSStreamLayerFromListener(ln, advertise, opts.TLSProvider)
		stream = NewRetryingStreamLayer(tlsLayer, opts.TLSProvider, opts.Timeout, opts.MaxDialRetries, opts.DialRetryBackoff, opts.Metrics)
	} else {
		plainLayer := newPlainStreamLayerFromListener(ln, advertise)
		stream = NewRetryingStreamLayer(plainLayer, nil, opts.Timeout, opts.MaxDialRetries, opts.DialRetryBackoff, opts.Metrics)
	}

	transport := hraft.NewNetworkTransportWithConfig(&hraft.NetworkTransportConfig{
		Stream:  stream,
		Logger:  hclog.New(&hclog.LoggerOptions{Output: opts.LogOutput, Name: "transport"}),
		MaxPool: opts.MaxPool,
		Timeout: opts.Timeout,
	})
	return transport, stream.(io.Closer), advertise.String(), nil
}

// ResolveAdvertiseAddr resolves advertiseAddr, retrying every second within
// the timeout budget so a cluster whose DNS is still warming up delays the
// pod instead of failing it out of the boot sequence.
func ResolveAdvertiseAddr(advertiseAddr string, timeout time.Duration, logOutput io.Writer) (*net.TCPAddr, error) {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	for {
		addr, err := net.ResolveTCPAddr("tcp", advertiseAddr)
		if err == nil {
			return addr, nil
		}
		if logOutput != nil {
			_, _ = fmt.Fprintf(logOutput, "[WARN] raft: unable to resolve advertise addr %s yet, retrying: %v\n", advertiseAddr, err)
		}
		if !time.Now().Add(time.Second).Before(deadline) {
			return nil, err
		}
		time.Sleep(time.Second)
	}
}
