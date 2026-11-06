package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"github.com/disaster37/raft/internal/fileutil"
)

const (
	generationKey       = "generation"
	localGenerationFile = "generation"
)

// GenerationStore reads and bumps the cluster generation stored in the CA
// Secret.
type GenerationStore struct {
	client    kubernetes.Interface
	namespace string
	secret    string
}

// NewGenerationStore returns a generation store.
func NewGenerationStore(client kubernetes.Interface, namespace, secretName string) *GenerationStore {
	return &GenerationStore{client: client, namespace: namespace, secret: secretName}
}

// ReadClusterGeneration returns the cluster generation. The second result is
// false when the Secret or key is absent.
func (g *GenerationStore) ReadClusterGeneration(ctx context.Context) (uint64, bool) {
	if g == nil || g.client == nil {
		return 0, false
	}
	secret, err := g.client.CoreV1().Secrets(g.namespace).Get(ctx, g.secret, metav1.GetOptions{})
	if err != nil {
		return 0, false
	}
	raw, ok := secret.Data[generationKey]
	if !ok {
		return 0, false
	}
	gen, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return 0, false
	}
	return gen, true
}

// BumpClusterGeneration increments the cluster generation and returns it.
func (g *GenerationStore) BumpClusterGeneration(ctx context.Context) (uint64, error) {
	if g == nil || g.client == nil {
		return 0, fmt.Errorf("generation store unavailable")
	}
	secrets := g.client.CoreV1().Secrets(g.namespace)
	var next uint64
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secret, err := secrets.Get(ctx, g.secret, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("read generation secret: %w", err)
		}
		current := uint64(0)
		if raw, ok := secret.Data[generationKey]; ok {
			if parsed, parseErr := strconv.ParseUint(string(raw), 10, 64); parseErr == nil {
				current = parsed
			}
		}
		next = current + 1
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[generationKey] = []byte(strconv.FormatUint(next, 10))
		if _, err := secrets.Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update generation secret: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return next, nil
}

// ReadLocalGeneration returns the generation this node last synchronized with.
func ReadLocalGeneration(dir string) (uint64, bool) {
	//nolint:gosec // fixed generation file under the data dir
	raw, err := os.ReadFile(filepath.Join(dir, localGenerationFile)) // #nosec G304
	if err != nil {
		return 0, false
	}
	gen, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return 0, false
	}
	return gen, true
}

// WriteLocalGeneration records the synchronized generation on disk.
func WriteLocalGeneration(dir string, gen uint64) error {
	return fileutil.WriteFile0600(filepath.Join(dir, localGenerationFile), []byte(strconv.FormatUint(gen, 10)))
}
