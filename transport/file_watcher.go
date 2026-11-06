package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/disaster37/raft/observ"
)

// FileWatcher polls cert/key/CA files and updates a DynamicTLSProvider.
type FileWatcher struct {
	certFile      string
	keyFile       string
	caFile        string
	pollInterval  time.Duration
	renewalWindow time.Duration
	clientAuth    bool
	logger        observ.Logger
	provider      *DynamicTLSProvider
	done          chan struct{}
	doneOnce      sync.Once
}

// NewFileWatcher loads the initial material and returns a watcher.
func NewFileWatcher(certFile, keyFile, caFile string, pollInterval, renewalWindow time.Duration, clientAuth bool, logger observ.Logger) (*FileWatcher, error) {
	if logger == nil {
		logger = observ.NewNoopLogger()
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	if renewalWindow <= 0 {
		renewalWindow = 7 * 24 * time.Hour
	}
	w := &FileWatcher{
		certFile:      certFile,
		keyFile:       keyFile,
		caFile:        caFile,
		pollInterval:  pollInterval,
		renewalWindow: renewalWindow,
		clientAuth:    clientAuth,
		logger:        logger,
		done:          make(chan struct{}),
	}
	if err := w.Reload(); err != nil {
		return nil, err
	}
	return w, nil
}

// Provider returns the underlying dynamic provider.
func (w *FileWatcher) Provider() *DynamicTLSProvider { return w.provider }

// Done is closed when Start returns.
func (w *FileWatcher) Done() <-chan struct{} { return w.done }

// Start polls the files until ctx is cancelled.
func (w *FileWatcher) Start(ctx context.Context) {
	defer w.doneOnce.Do(func() { close(w.done) })
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.Reload(); err != nil {
				w.logger.Warn("tls file watcher: reload rejected, keeping previous certificate", map[string]any{"error": err.Error()})
			}
		}
	}
}

// Reload reads and validates the files, updating the provider on success.
func (w *FileWatcher) Reload() error {
	leaf, err := tls.LoadX509KeyPair(w.certFile, w.keyFile)
	if err != nil {
		return fmt.Errorf("load key pair: %w", err)
	}
	if len(leaf.Certificate) == 0 {
		return fmt.Errorf("load key pair: empty certificate chain")
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}
	leaf.Leaf = parsed
	now := time.Now()
	if now.Before(parsed.NotBefore) {
		return fmt.Errorf("certificate not yet valid (notBefore %s)", parsed.NotBefore.Format(time.RFC3339))
	}
	if now.After(parsed.NotAfter) {
		return fmt.Errorf("certificate expired at %s", parsed.NotAfter.Format(time.RFC3339))
	}
	if time.Until(parsed.NotAfter) < w.renewalWindow {
		w.logger.Warn("tls file watcher: certificate expires soon", map[string]any{
			"not_after": parsed.NotAfter.Format(time.RFC3339),
		})
	}
	caPEM, err := os.ReadFile(filepath.Clean(w.caFile))
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("no CA certificate found in %s", w.caFile)
	}
	if w.provider == nil {
		w.provider = NewDynamicTLSProvider(leaf, pool, pool, w.clientAuth)
		return nil
	}
	w.provider.Update(leaf, pool, pool)
	return nil
}
