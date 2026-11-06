package keyring

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/observ"
	"github.com/disaster37/raft/storage"
)

// KeyringApplier abstracts Raft leadership and FSM keyring persistence for
// PhasedRotator.
type KeyringApplier interface {
	IsLeader() bool
	AppliedIndex() uint64
	MinFollowerAppliedIndex() uint64
	ReadKeyring() (*TLSKeyring, error)
	ApplyKeyring(ctx context.Context, kr *TLSKeyring) (uint64, error)
}

// RotatorConfig configures a PhasedRotator.
type RotatorConfig struct {
	PKIMode        config.PKIMode
	CommonName     string
	Organization   string
	DNSNames       []string
	IPAddrs        []net.IP
	Validity       time.Duration
	RotationPeriod time.Duration
	CheckInterval  time.Duration
	Sealer         storage.Sealer
	Manager        *Manager
	Applier        KeyringApplier
	Logger         observ.Logger
	Metrics        observ.MetricsCollector
	NowFunc        func() time.Time
	// Seed optionally supplies the initial keyring (for example from the
	// pre-Raft bootstrap CA). When nil, RotateOnce generates a fresh key.
	Seed func(ctx context.Context) (*TLSKeyring, error)
}

// PhasedRotator runs the Vault-style two-phase key/CA rotation loop on the
// leader.
type PhasedRotator struct {
	cfg RotatorConfig
}

// NewPhasedRotator returns a phased rotator.
func NewPhasedRotator(cfg RotatorConfig) *PhasedRotator {
	if cfg.Logger == nil {
		cfg.Logger = observ.NewNoopLogger()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = observ.NewNoopMetrics()
	}
	if cfg.NowFunc == nil {
		cfg.NowFunc = time.Now
	}
	if cfg.RotationPeriod <= 0 {
		cfg.RotationPeriod = 24 * time.Hour
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 30 * time.Second
	}
	if cfg.Validity <= 0 {
		cfg.Validity = 365 * 24 * time.Hour
	}
	return &PhasedRotator{cfg: cfg}
}

// Start runs the rotation loop until ctx is cancelled.
func (r *PhasedRotator) Start(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if r.cfg.Applier == nil || !r.cfg.Applier.IsLeader() {
				continue
			}
			if _, err := r.RotateOnce(ctx); err != nil {
				r.cfg.Logger.Warn("keyring rotation failed", map[string]any{"error": err.Error()})
				r.cfg.Metrics.IncKeyringRotations("error")
			}
			if _, err := r.CheckCommitted(ctx); err != nil {
				r.cfg.Logger.Warn("keyring activation failed", map[string]any{"error": err.Error()})
				r.cfg.Metrics.IncKeyringRotations("error")
			}
		}
	}
}

// RotateOnce performs Phase 1 (stage a new key and record its applied index).
func (r *PhasedRotator) RotateOnce(ctx context.Context) (time.Time, error) {
	if r.cfg.Applier == nil || !r.cfg.Applier.IsLeader() {
		return time.Time{}, nil
	}
	now := r.cfg.NowFunc()
	kr, err := r.cfg.Applier.ReadKeyring()
	if err != nil {
		return time.Time{}, fmt.Errorf("read keyring: %w", err)
	}
	if kr == nil {
		if r.cfg.Seed != nil {
			seeded, err := r.cfg.Seed(ctx)
			if err != nil {
				return time.Time{}, fmt.Errorf("seed keyring: %w", err)
			}
			if seeded == nil {
				return time.Time{}, nil
			}
			kr = seeded
		} else {
			key, err := GenerateTLSKeyWithGoca(r.cfg.PKIMode, r.cfg.CommonName, r.cfg.Organization, r.cfg.DNSNames, r.cfg.IPAddrs, r.cfg.Validity, r.cfg.Sealer, now)
			if err != nil {
				return time.Time{}, err
			}
			kr = &TLSKeyring{Keys: []*TLSKey{key}, ActiveKeyID: key.ID, Term: 1}
		}
		idx, err := r.cfg.Applier.ApplyKeyring(ctx, kr)
		if err != nil {
			return time.Time{}, fmt.Errorf("apply initial keyring: %w", err)
		}
		kr.AppliedIndex = idx
		if active := kr.GetActive(); active != nil {
			active.AppliedIndex = idx
		}
		if _, err := r.cfg.Applier.ApplyKeyring(ctx, kr); err != nil {
			return time.Time{}, fmt.Errorf("commit initial keyring index: %w", err)
		}
		r.cfg.Metrics.IncKeyringRotations("initialized")
		return now, nil
	}

	if len(kr.Keys) == 2 && kr.Keys[1].AppliedIndex == 0 {
		idx := r.cfg.Applier.AppliedIndex()
		if idx == 0 {
			idx = 1
		}
		kr.AppliedIndex = idx
		kr.Keys[1].AppliedIndex = idx
		if _, err := r.cfg.Applier.ApplyKeyring(ctx, kr); err != nil {
			return time.Time{}, fmt.Errorf("complete phase 1: %w", err)
		}
		r.cfg.Metrics.IncKeyringRotations("staged")
		return now, nil
	}

	if len(kr.Keys) == 2 {
		return time.Time{}, nil
	}
	if len(kr.Keys) != 1 {
		return time.Time{}, fmt.Errorf("keyring has %d keys, expected 1 or 2", len(kr.Keys))
	}
	active := kr.GetActive()
	if active == nil {
		return time.Time{}, fmt.Errorf("keyring has no active key")
	}
	if now.Sub(active.CreatedTime) < r.cfg.RotationPeriod {
		return time.Time{}, nil
	}
	key, err := GenerateTLSKeyWithGoca(r.cfg.PKIMode, r.cfg.CommonName, r.cfg.Organization, r.cfg.DNSNames, r.cfg.IPAddrs, r.cfg.Validity, r.cfg.Sealer, now)
	if err != nil {
		return time.Time{}, err
	}
	kr.Keys = append(kr.Keys, key)
	kr.Term++
	kr.AppliedIndex = 0
	if _, err := r.cfg.Applier.ApplyKeyring(ctx, kr); err != nil {
		return time.Time{}, fmt.Errorf("stage new key: %w", err)
	}
	r.cfg.Metrics.IncKeyringRotations("staged")
	return now, nil
}

// CheckCommitted performs Phase 2 (promote the new key and prune the old one)
// once every follower has applied the staged keyring.
func (r *PhasedRotator) CheckCommitted(ctx context.Context) (bool, error) {
	if r.cfg.Applier == nil || !r.cfg.Applier.IsLeader() {
		return false, nil
	}
	kr, err := r.cfg.Applier.ReadKeyring()
	if err != nil {
		return false, fmt.Errorf("read keyring: %w", err)
	}
	if kr == nil || len(kr.Keys) != 2 || kr.AppliedIndex == 0 {
		return false, nil
	}
	if r.cfg.Applier.MinFollowerAppliedIndex() < kr.AppliedIndex {
		return false, nil
	}
	next := &TLSKeyring{
		Keys:         []*TLSKey{kr.Keys[1]},
		ActiveKeyID:  kr.Keys[1].ID,
		Term:         kr.Term + 1,
		AppliedIndex: 0,
	}
	if _, err := r.cfg.Applier.ApplyKeyring(ctx, next); err != nil {
		return false, fmt.Errorf("activate new key: %w", err)
	}
	r.cfg.Metrics.IncKeyringRotations("activated")
	return true, nil
}
