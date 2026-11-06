// Package storage provides Raft log/stable/snapshot backends and at-rest
// encryption helpers.
package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/disaster37/raft/internal/fileutil"
)

// EncryptedValue is the JSON envelope of one at-rest encrypted value.
type EncryptedValue struct {
	KID string `json:"kid"`
	Alg string `json:"alg"`
	Ver int    `json:"ver"`
	Non string `json:"non"`
	Ctx string `json:"ctx"`
	Ct  string `json:"ct"`
}

// Sealer encrypts and decrypts sensitive values at rest.
type Sealer interface {
	Seal(plain []byte) (EncryptedValue, error)
	Open(ev EncryptedValue) ([]byte, error)
	SealString(plain string) (string, error)
	OpenString(stored string) (string, error)
}

// AESGCMKeeper implements Sealer using AES-256-GCM with key rotation.
type AESGCMKeeper struct {
	keys    map[string][]byte
	primary string
	aad     string
}

type cryptoKeyFile struct {
	Primary string            `json:"primary"`
	Keys    map[string]string `json:"keys"`
}

// LoadAESGCMKeeper loads {"primary":"k1","keys":{"k1":"<base64 32B>"}}.
func LoadAESGCMKeeper(keyFile string, aadContext string) (*AESGCMKeeper, error) {
	data, err := os.ReadFile(filepath.Clean(keyFile))
	if err != nil {
		return nil, fmt.Errorf("read at-rest key file: %w", err)
	}
	var parsed cryptoKeyFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse at-rest key file: %w", err)
	}
	if parsed.Primary == "" || len(parsed.Keys) == 0 {
		return nil, fmt.Errorf("at-rest key file must define primary and keys")
	}
	keys := make(map[string][]byte, len(parsed.Keys))
	for kid, b64 := range parsed.Keys {
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode key %q: %w", kid, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("key %q must be 32 bytes (got %d)", kid, len(key))
		}
		keys[kid] = key
	}
	if _, ok := keys[parsed.Primary]; !ok {
		return nil, fmt.Errorf("primary key %q not present in keys", parsed.Primary)
	}
	return &AESGCMKeeper{keys: keys, primary: parsed.Primary, aad: aadContext}, nil
}

// NewAESGCMKeeper builds a keeper from raw 32-byte keys.
func NewAESGCMKeeper(primary string, keys map[string][]byte, aadContext string) (*AESGCMKeeper, error) {
	if primary == "" {
		return nil, fmt.Errorf("at-rest primary key is required")
	}
	if _, ok := keys[primary]; !ok {
		return nil, fmt.Errorf("primary key %q not present in keys", primary)
	}
	for kid, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("key %q must be 32 bytes (got %d)", kid, len(key))
		}
	}
	return &AESGCMKeeper{keys: keys, primary: primary, aad: aadContext}, nil
}

// GenerateKeyFile writes a fresh single-key at-rest key file.
func GenerateKeyFile(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate at-rest key: %w", err)
	}
	doc := cryptoKeyFile{Primary: "k1", Keys: map[string]string{"k1": base64.StdEncoding.EncodeToString(key)}}
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal at-rest key file: %w", err)
	}
	return fileutil.WriteFile0600(path, data)
}

// Timeout returns the recommended BoltDB open timeout.
func (k *AESGCMKeeper) Timeout() time.Duration { return time.Second }

// Seal encrypts plaintext under the primary key.
func (k *AESGCMKeeper) Seal(plain []byte) (EncryptedValue, error) {
	key, ok := k.keys[k.primary]
	if !ok {
		return EncryptedValue{}, fmt.Errorf("primary at-rest key %q missing", k.primary)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedValue{}, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedValue{}, fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedValue{}, fmt.Errorf("generate nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plain, []byte(k.aad))
	return EncryptedValue{
		KID: k.primary,
		Alg: "A256GCM",
		Ver: 1,
		Non: base64.StdEncoding.EncodeToString(nonce),
		Ctx: base64.StdEncoding.EncodeToString([]byte(k.aad)),
		Ct:  base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Open decrypts an EncryptedValue using its key ID.
func (k *AESGCMKeeper) Open(ev EncryptedValue) ([]byte, error) {
	if ev.Alg != "A256GCM" || ev.Ver != 1 {
		return nil, fmt.Errorf("unsupported at-rest envelope alg=%q ver=%d", ev.Alg, ev.Ver)
	}
	key, ok := k.keys[ev.KID]
	if !ok {
		return nil, fmt.Errorf("unknown at-rest key %q", ev.KID)
	}
	nonce, err := base64.StdEncoding.DecodeString(ev.Non)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ev.Ct)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	ctx, err := base64.StdEncoding.DecodeString(ev.Ctx)
	if err != nil {
		return nil, fmt.Errorf("decode context: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ct, ctx)
	if err != nil {
		return nil, fmt.Errorf("decrypt at-rest value: %w", err)
	}
	return plain, nil
}

// SealString seals plaintext and returns the JSON envelope.
func (k *AESGCMKeeper) SealString(plain string) (string, error) {
	ev, err := k.Seal([]byte(plain))
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return "", fmt.Errorf("marshal at-rest envelope: %w", err)
	}
	return string(data), nil
}

// OpenString opens a stored value. Values that are not a valid encrypted
// envelope are returned unchanged (lazy plaintext migration).
func (k *AESGCMKeeper) OpenString(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	var ev EncryptedValue
	if err := json.Unmarshal([]byte(stored), &ev); err != nil || ev.Alg == "" || ev.Ct == "" {
		return stored, nil
	}
	plain, err := k.Open(ev)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
