package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/disaster37/go-raft/internal/fileutil"
	"github.com/disaster37/go-raft/observ"
	"github.com/disaster37/go-raft/pki"
)

var errEmptySecret = errors.New("bootstrap CA secret exists but ca.crt/ca.key are empty")

// SecretBootstrapConfig configures a SecretBootstrapProvider.
type SecretBootstrapConfig struct {
	Clientset    kubernetes.Interface
	Namespace    string
	SecretName   string
	CABootstrap  bool
	CACommonName string
	Organization string
	CAValidity   time.Duration
	PollTimeout  time.Duration
	PollInterval time.Duration
	CacheDir     string
	Logger       observ.Logger
}

// SecretBootstrapProvider implements pki.BootstrapProvider using a Kubernetes
// Secret.
type SecretBootstrapProvider struct {
	cfg SecretBootstrapConfig
}

// NewSecretBootstrapProvider returns a Secret-backed bootstrap provider.
func NewSecretBootstrapProvider(cfg SecretBootstrapConfig) *SecretBootstrapProvider {
	if cfg.Logger == nil {
		cfg.Logger = observ.NewNoopLogger()
	}
	if cfg.PollTimeout <= 0 {
		cfg.PollTimeout = 120 * time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	if cfg.CACommonName == "" {
		cfg.CACommonName = "raft-ca"
	}
	if cfg.Organization == "" {
		cfg.Organization = "raft"
	}
	return &SecretBootstrapProvider{cfg: cfg}
}

// EnsureBootstrapMaterial returns the shared CA, creating it on the bootstrap
// node and polling on followers.
func (p *SecretBootstrapProvider) EnsureBootstrapMaterial(ctx context.Context) (*pki.BootstrapMaterial, error) {
	if p.cfg.Clientset == nil {
		return nil, fmt.Errorf("secret bootstrap: clientset is required")
	}
	if p.cfg.Namespace == "" || p.cfg.SecretName == "" {
		return nil, fmt.Errorf("secret bootstrap: namespace and secret name are required")
	}
	if mat, err := p.readSecret(ctx); err == nil {
		return mat, nil
	} else if !apierrors.IsNotFound(err) && !errors.Is(err, errEmptySecret) {
		return nil, fmt.Errorf("secret bootstrap: read secret %s: %w", p.cfg.SecretName, err)
	}

	if p.cfg.CABootstrap {
		return p.createSecret(ctx)
	}
	return p.pollSecret(ctx)
}

func (p *SecretBootstrapProvider) createSecret(ctx context.Context) (*pki.BootstrapMaterial, error) {
	ca, err := pki.NewMintingCA(p.cfg.CACommonName, p.cfg.Organization, p.cfg.CAValidity)
	if err != nil {
		return nil, err
	}
	certPEM, keyPEM, err := ca.EncodePEM()
	if err != nil {
		return nil, err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: p.cfg.SecretName, Namespace: p.cfg.Namespace},
		Data:       map[string][]byte{"ca.crt": certPEM, "ca.key": keyPEM},
	}
	if _, err := p.cfg.Clientset.CoreV1().Secrets(p.cfg.Namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("secret bootstrap: create secret %s: %w", p.cfg.SecretName, err)
		}
		if mat, readErr := p.readSecret(ctx); readErr == nil {
			return mat, nil
		} else if !errors.Is(readErr, errEmptySecret) {
			return nil, fmt.Errorf("secret bootstrap: read existing secret %s: %w", p.cfg.SecretName, readErr)
		}
		if _, err := p.cfg.Clientset.CoreV1().Secrets(p.cfg.Namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
			return nil, fmt.Errorf("secret bootstrap: update empty secret %s: %w", p.cfg.SecretName, err)
		}
	}
	p.cfg.Logger.Info("secret bootstrap: created CA secret", map[string]any{"secret": p.cfg.SecretName})
	mat := &pki.BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}
	if err := p.cache(mat); err != nil {
		return nil, err
	}
	return mat, nil
}

func (p *SecretBootstrapProvider) pollSecret(ctx context.Context) (*pki.BootstrapMaterial, error) {
	deadline := time.Now().Add(p.cfg.PollTimeout)
	for {
		mat, err := p.readSecret(ctx)
		if err == nil {
			return mat, nil
		}
		if !apierrors.IsNotFound(err) && !errors.Is(err, errEmptySecret) {
			return nil, fmt.Errorf("secret bootstrap: read secret %s: %w", p.cfg.SecretName, err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("secret bootstrap: secret %s did not appear within %s: %w", p.cfg.SecretName, p.cfg.PollTimeout, err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("secret bootstrap: %w", ctx.Err())
		case <-time.After(p.cfg.PollInterval):
		}
	}
}

func (p *SecretBootstrapProvider) readSecret(ctx context.Context) (*pki.BootstrapMaterial, error) {
	secret, err := p.cfg.Clientset.CoreV1().Secrets(p.cfg.Namespace).Get(ctx, p.cfg.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	certPEM, okCert := secret.Data["ca.crt"]
	keyPEM, okKey := secret.Data["ca.key"]
	if !okCert || !okKey || len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, errEmptySecret
	}
	mat := &pki.BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}
	if err := p.cache(mat); err != nil {
		return nil, err
	}
	return mat, nil
}

func (p *SecretBootstrapProvider) cache(mat *pki.BootstrapMaterial) error {
	if p.cfg.CacheDir == "" {
		return nil
	}
	if err := fileutil.EnsureDir0700(p.cfg.CacheDir); err != nil {
		return err
	}
	if err := fileutil.WriteFile0600(filepath.Join(p.cfg.CacheDir, "ca.crt"), mat.CACertPEM); err != nil {
		return err
	}
	if len(mat.CAKeyPEM) > 0 {
		if err := fileutil.WriteFile0600(filepath.Join(p.cfg.CacheDir, "ca.key"), mat.CAKeyPEM); err != nil {
			return err
		}
	}
	return nil
}

// ReadCachedMaterial loads cached CA material from dir, if present.
func ReadCachedMaterial(dir string) (*pki.BootstrapMaterial, error) {
	//nolint:gosec // fixed cache file under the configured cache dir
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt")) // #nosec G304
	if err != nil {
		return nil, err
	}
	//nolint:gosec // fixed cache file under the configured cache dir
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key")) // #nosec G304
	if err != nil {
		return nil, err
	}
	return &pki.BootstrapMaterial{CACertPEM: certPEM, CAKeyPEM: keyPEM}, nil
}
