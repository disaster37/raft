// Package storage provides Raft log/stable/snapshot backends and at-rest
// encryption helpers.
package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/internal/fileutil"
)

const (
	// DefaultHKDFInfo is the default domain-separation info string for
	// HKDF-SHA256.
	DefaultHKDFInfo = "raft-at-rest-aes-256-gcm-v1"
	// DefaultDerivedKeyID is the key ID used for HKDF-derived keepers.
	DefaultDerivedKeyID = "derived"
	// MinSecretLength is the minimum input secret length (in bytes) for HKDF
	// derivation.
	MinSecretLength = 16
)

// ErrSecretTooShort is returned when the input secret to DeriveAESGCMKey or
// DeriveAESGCMKeeper is shorter than MinSecretLength (16 bytes).
var ErrSecretTooShort = errors.New("storage: at-rest secret must be at least 16 bytes")

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
	return loadAESGCMKeeperFromBytes(data, aadContext)
}

func loadAESGCMKeeperFromBytes(data []byte, aadContext string) (*AESGCMKeeper, error) {
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

// DeriveAESGCMKey derives a 32-byte AES-256 key from secret using HKDF-SHA256
// with domain-separation string info (defaulting to DefaultHKDFInfo when
// empty). Returns ErrSecretTooShort if len(secret) < MinSecretLength.
func DeriveAESGCMKey(secret []byte, info string) ([]byte, error) {
	if len(secret) < MinSecretLength {
		return nil, fmt.Errorf("%w (got %d)", ErrSecretTooShort, len(secret))
	}
	if info == "" {
		info = DefaultHKDFInfo
	}
	key, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("derive AES-256 key via HKDF: %w", err)
	}
	return key, nil
}

// DeriveAESGCMKeeper derives a 32-byte AES-256 key from secret using
// DeriveAESGCMKey(secret, info) and returns an AESGCMKeeper with primary key
// ID DefaultDerivedKeyID and the given aadContext.
func DeriveAESGCMKeeper(secret []byte, info, aadContext string) (*AESGCMKeeper, error) {
	key, err := DeriveAESGCMKey(secret, info)
	if err != nil {
		return nil, err
	}
	return NewAESGCMKeeper(DefaultDerivedKeyID, map[string][]byte{DefaultDerivedKeyID: key}, aadContext)
}

// LoadOrDeriveAESGCMKeeper constructs an AESGCMKeeper from cfg. A JSON key
// file is loaded as-is; a raw secret file or cfg.AtRestKey is expanded with
// HKDF-SHA256. When neither is configured it returns (nil, nil).
func LoadOrDeriveAESGCMKeeper(cfg config.StorageConfig) (*AESGCMKeeper, error) {
	if cfg.AtRestKeyFile != "" {
		raw, err := os.ReadFile(filepath.Clean(cfg.AtRestKeyFile))
		if err != nil {
			return nil, fmt.Errorf("read at-rest key file: %w", err)
		}
		// Only treat the file as a JSON key file when it actually looks like
		// one. A malformed JSON key file (valid JSON with a bad key) must
		// surface its validation error instead of being silently re-derived as
		// a raw secret, which would produce a different key and make previously
		// encrypted data undecryptable.
		var parsed cryptoKeyFile
		if jsonErr := json.Unmarshal(raw, &parsed); jsonErr == nil && (parsed.Primary != "" || len(parsed.Keys) > 0) {
			return loadAESGCMKeeperFromBytes(raw, cfg.AtRestKeyInfo)
		}
		secret := bytes.TrimSpace(raw)
		if len(secret) < MinSecretLength {
			return nil, fmt.Errorf("%w (got %d)", ErrSecretTooShort, len(secret))
		}
		return DeriveAESGCMKeeper(secret, cfg.AtRestKeyInfo, cfg.AtRestKeyInfo)
	}
	if cfg.AtRestKey != "" {
		return DeriveAESGCMKeeper([]byte(cfg.AtRestKey), cfg.AtRestKeyInfo, cfg.AtRestKeyInfo)
	}
	return nil, nil
}

// NewAESGCMKeeper builds a keeper from raw 32-byte keys. The keys map and
// each key slice are copied so caller mutation cannot corrupt the keeper.
func NewAESGCMKeeper(primary string, keys map[string][]byte, aadContext string) (*AESGCMKeeper, error) {
	if primary == "" {
		return nil, fmt.Errorf("at-rest primary key is required")
	}
	if _, ok := keys[primary]; !ok {
		return nil, fmt.Errorf("primary key %q not present in keys", primary)
	}
	copied := make(map[string][]byte, len(keys))
	for kid, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("key %q must be 32 bytes (got %d)", kid, len(key))
		}
		copied[kid] = append([]byte(nil), key...)
	}
	return &AESGCMKeeper{keys: copied, primary: primary, aad: aadContext}, nil
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
