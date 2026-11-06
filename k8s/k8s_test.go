package k8s

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/retry"

	"github.com/disaster37/raft/pki"
)

func TestSecretBootstrapOrdinal0Creates(t *testing.T) {
	client := fake.NewSimpleClientset()
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset:    client,
		Namespace:    "ns",
		SecretName:   "ca",
		CABootstrap:  true,
		CACommonName: "ca",
		Organization: "org",
		CAValidity:   time.Hour,
		CacheDir:     t.TempDir(),
	})
	mat, err := provider.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatalf("EnsureBootstrapMaterial: %v", err)
	}
	if len(mat.CACertPEM) == 0 || len(mat.CAKeyPEM) == 0 {
		t.Fatal("missing CA material")
	}
	secret, err := client.CoreV1().Secrets("ns").Get(context.Background(), "ca", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if len(secret.Data["ca.crt"]) == 0 || len(secret.Data["ca.key"]) == 0 {
		t.Fatal("secret missing CA data")
	}
}

func TestSecretBootstrapOrdinal0ReusesExisting(t *testing.T) {
	client := fake.NewSimpleClientset()
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", CABootstrap: true, CAValidity: time.Hour,
	})
	first, err := provider.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(first.CACertPEM) != string(second.CACertPEM) {
		t.Fatal("expected CA reuse")
	}
}

func TestSecretBootstrapEmptySecretOverwritten(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"ca.crt": {}, "ca.key": {}},
	})
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", CABootstrap: true, CAValidity: time.Hour,
	})
	mat, err := provider.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatalf("EnsureBootstrapMaterial: %v", err)
	}
	if len(mat.CACertPEM) == 0 {
		t.Fatal("empty secret was not overwritten")
	}
}

func TestSecretBootstrapFollowerPollsUntilCreated(t *testing.T) {
	client := fake.NewSimpleClientset()
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = client.CoreV1().Secrets("ns").Create(context.Background(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
			Data:       map[string][]byte{"ca.crt": []byte("cert"), "ca.key": []byte("key")},
		}, metav1.CreateOptions{})
	}()
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", PollTimeout: time.Second, PollInterval: 10 * time.Millisecond,
	})
	mat, err := provider.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatalf("EnsureBootstrapMaterial: %v", err)
	}
	if string(mat.CACertPEM) != "cert" {
		t.Fatalf("cert = %q", mat.CACertPEM)
	}
}

func TestSecretBootstrapRBACErrorFailsFast(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "ca", errors.New("denied"))
	})
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", PollTimeout: time.Second, PollInterval: 10 * time.Millisecond,
	})
	if _, err := provider.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected RBAC error")
	}
}

func TestSecretBootstrapPollTimeout(t *testing.T) {
	client := fake.NewSimpleClientset()
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", PollTimeout: 30 * time.Millisecond, PollInterval: 10 * time.Millisecond,
	})
	if _, err := provider.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestSecretBootstrapRequiresConfig(t *testing.T) {
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{})
	if _, err := provider.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected clientset error")
	}
	provider = NewSecretBootstrapProvider(SecretBootstrapConfig{Clientset: fake.NewSimpleClientset()})
	if _, err := provider.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected namespace error")
	}
}

func TestGenerationStoreReadAndBump(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"generation": []byte("4")},
	})
	store := NewGenerationStore(client, "ns", "ca")
	gen, ok := store.ReadClusterGeneration(context.Background())
	if !ok || gen != 4 {
		t.Fatalf("gen = %d ok=%v", gen, ok)
	}
	next, err := store.BumpClusterGeneration(context.Background())
	if err != nil || next != 5 {
		t.Fatalf("next = %d err=%v", next, err)
	}
	gen, ok = store.ReadClusterGeneration(context.Background())
	if !ok || gen != 5 {
		t.Fatalf("gen = %d ok=%v", gen, ok)
	}
	if _, ok := NewGenerationStore(client, "ns", "missing").ReadClusterGeneration(context.Background()); ok {
		t.Fatal("expected missing generation")
	}
	if _, err := NewGenerationStore(client, "ns", "missing").BumpClusterGeneration(context.Background()); err == nil {
		t.Fatal("expected bump error")
	}
	if _, err := (*GenerationStore)(nil).BumpClusterGeneration(context.Background()); err == nil {
		t.Fatal("expected nil store error")
	}
}

func TestGenerationBumpRetriesOnConflict(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"generation": []byte("4")},
	})
	var updates int
	client.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		if updates == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, "ca", errors.New("conflict"))
		}
		return false, nil, nil
	})
	store := NewGenerationStore(client, "ns", "ca")
	next, err := store.BumpClusterGeneration(context.Background())
	if err != nil || next != 5 {
		t.Fatalf("next = %d err=%v", next, err)
	}
	if updates != 2 {
		t.Fatalf("updates = %d, want 2", updates)
	}
	secret, err := client.CoreV1().Secrets("ns").Get(context.Background(), "ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["generation"]) != "5" {
		t.Fatalf("generation = %q", secret.Data["generation"])
	}
}

func TestGenerationBumpConflictIsBounded(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"generation": []byte("1")},
	})
	var updates int
	client.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, "ca", errors.New("conflict"))
	})
	store := NewGenerationStore(client, "ns", "ca")
	if _, err := store.BumpClusterGeneration(context.Background()); err == nil {
		t.Fatal("expected conflict error")
	}
	if updates != retry.DefaultRetry.Steps {
		t.Fatalf("updates = %d, want %d", updates, retry.DefaultRetry.Steps)
	}
}

func TestLocalGeneration(t *testing.T) {
	dir := t.TempDir()
	if _, ok := ReadLocalGeneration(dir); ok {
		t.Fatal("expected missing generation")
	}
	if err := WriteLocalGeneration(dir, 7); err != nil {
		t.Fatal(err)
	}
	gen, ok := ReadLocalGeneration(dir)
	if !ok || gen != 7 {
		t.Fatalf("gen = %d ok=%v", gen, ok)
	}
}

func TestStatefulSetReplicaReader(t *testing.T) {
	replicas := int32(1)
	client := fake.NewSimpleClientset(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "sts", Namespace: "ns"},
		Spec:       appsv1.StatefulSetSpec{Replicas: &replicas},
	})
	reader := NewStatefulSetReplicaReader(client, "ns", "sts")
	got, ok := reader.Replicas(context.Background())
	if !ok || got != 1 {
		t.Fatalf("replicas = %d ok=%v", got, ok)
	}
	if _, ok := NewStatefulSetReplicaReader(client, "ns", "missing").Replicas(context.Background()); ok {
		t.Fatal("expected missing statefulset")
	}
	if _, ok := (*StatefulSetReplicaReader)(nil).Replicas(context.Background()); ok {
		t.Fatal("expected nil reader")
	}
}

func TestReadCachedMaterial(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadCachedMaterial(dir); err == nil {
		t.Fatal("expected missing cache error")
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	mat, err := ReadCachedMaterial(dir)
	if err != nil || string(mat.CACertPEM) != "cert" || string(mat.CAKeyPEM) != "key" {
		t.Fatalf("mat = %+v err=%v", mat, err)
	}
}

func TestNewClientsetFromKubeconfig(t *testing.T) {
	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "config")
	content := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: test
`
	if err := os.WriteFile(kubeconfig, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)
	client, err := NewClientset()
	if err != nil {
		t.Fatalf("NewClientset: %v", err)
	}
	if client == nil {
		t.Fatal("nil clientset")
	}
}

func TestSecretBootstrapAlreadyExistsValid(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.EncodePEM()
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"ca.crt": certPEM, "ca.key": keyPEM},
	})
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", CABootstrap: true, CAValidity: time.Hour,
	})
	mat, err := provider.EnsureBootstrapMaterial(context.Background())
	if err != nil {
		t.Fatalf("EnsureBootstrapMaterial: %v", err)
	}
	if string(mat.CACertPEM) != string(certPEM) {
		t.Fatal("expected existing CA reuse")
	}
}

func TestSecretBootstrapCacheError(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset()
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", CABootstrap: true, CAValidity: time.Hour, CacheDir: file,
	})
	if _, err := provider.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected cache error")
	}
}

func TestGenerationStoreInvalidValue(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"generation": []byte("bad")},
	})
	store := NewGenerationStore(client, "ns", "ca")
	if _, ok := store.ReadClusterGeneration(context.Background()); ok {
		t.Fatal("expected invalid generation")
	}
}

func TestStatefulSetReplicaReaderNilReplicas(t *testing.T) {
	client := fake.NewSimpleClientset(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "sts", Namespace: "ns"},
	})
	reader := NewStatefulSetReplicaReader(client, "ns", "sts")
	if _, ok := reader.Replicas(context.Background()); ok {
		t.Fatal("expected nil replicas")
	}
}

func TestSecretBootstrapCreateError(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("create failed")
	})
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", CABootstrap: true, CAValidity: time.Hour,
	})
	if _, err := provider.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected create error")
	}
}

func TestGenerationStoreNilAndInvalidBump(t *testing.T) {
	if _, ok := (*GenerationStore)(nil).ReadClusterGeneration(context.Background()); ok {
		t.Fatal("nil store should not read")
	}
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"generation": []byte("bad")},
	})
	store := NewGenerationStore(client, "ns", "ca")
	next, err := store.BumpClusterGeneration(context.Background())
	if err != nil || next != 1 {
		t.Fatalf("next = %d err=%v", next, err)
	}
}

func TestSecretBootstrapPollContextCanceled(t *testing.T) {
	client := fake.NewSimpleClientset()
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", PollTimeout: time.Second, PollInterval: time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.EnsureBootstrapMaterial(ctx); err == nil {
		t.Fatal("expected context error")
	}
}

func TestReadLocalGenerationParseError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "generation"), []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadLocalGeneration(dir); ok {
		t.Fatal("expected parse error")
	}
}

func TestReadCachedMaterialMissingKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCachedMaterial(dir); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestGenerationBumpUpdateError(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"generation": []byte("1")},
	})
	client.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("update failed")
	})
	store := NewGenerationStore(client, "ns", "ca")
	if _, err := store.BumpClusterGeneration(context.Background()); err == nil {
		t.Fatal("expected update error")
	}
}

func TestSecretBootstrapCreateReadError(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, "ca")
	})
	client.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("read failed")
	})
	provider := NewSecretBootstrapProvider(SecretBootstrapConfig{
		Clientset: client, Namespace: "ns", SecretName: "ca", CABootstrap: true, CAValidity: time.Hour,
	})
	if _, err := provider.EnsureBootstrapMaterial(context.Background()); err == nil {
		t.Fatal("expected read error")
	}
}

func TestNewClientsetInCluster(t *testing.T) {
	dir := "/var/run/secrets/kubernetes.io/serviceaccount"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Skipf("cannot create service account dir: %v", err)
	}
	tokenPath := filepath.Join(dir, "token")
	caPath := filepath.Join(dir, "ca.crt")
	nsPath := filepath.Join(dir, "namespace")
	created := []string{}
	for path, content := range map[string]string{
		tokenPath: "token",
		caPath:    "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
		nsPath:    "default",
	} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Skipf("cannot write %s: %v", path, err)
			}
			created = append(created, path)
		}
	}
	t.Cleanup(func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	})
	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")
	client, err := NewClientset()
	if err != nil {
		t.Fatalf("NewClientset in cluster: %v", err)
	}
	if client == nil {
		t.Fatal("nil clientset")
	}
}
