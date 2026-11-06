package raft

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	hraft "github.com/hashicorp/raft"
)

// RecoverPeersJSON writes a peers.json recovery file into dir. It is a
// last-resort manual recovery mechanism; prefer SingleNodeRecovery or
// RecoveryMode.
func RecoverPeersJSON(dir string, servers []hraft.Server) error {
	if dir == "" {
		return fmt.Errorf("recover peers.json: empty dir")
	}
	if len(servers) == 0 {
		return fmt.Errorf("recover peers.json: no servers")
	}
	data, err := json.Marshal(servers)
	if err != nil {
		return fmt.Errorf("marshal peers.json: %w", err)
	}
	path := filepath.Join(dir, "peers.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write peers.json: %w", err)
	}
	return nil
}
