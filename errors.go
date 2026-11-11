package raft

import (
	"errors"

	"github.com/disaster37/go-raft/fsm"
)

var (
	// ErrNotLeader is returned when a write is attempted on a follower.
	ErrNotLeader = errors.New("raft: node is not the leader")
	// ErrRaftTimeout is returned when an apply or membership operation times out.
	ErrRaftTimeout = errors.New("raft: apply timed out")
	// ErrNodeRemoved is returned when the local node has been removed from the
	// cluster configuration.
	ErrNodeRemoved = errors.New("raft: node has been removed from cluster")
	// ErrAlreadyClosed is returned when an operation is attempted on a closed node.
	ErrAlreadyClosed = errors.New("raft: node is already closed")
	// ErrInvalidConfig is returned when the supplied configuration is invalid.
	ErrInvalidConfig = errors.New("raft: invalid configuration")
	// ErrBootstrapTimeout is returned when pre-Raft bootstrap material does not
	// appear within the configured timeout.
	ErrBootstrapTimeout = errors.New("raft: bootstrap material poll timed out")
	// ErrConflict is returned when a create-only KV mutation targets an
	// existing key.
	ErrConflict = fsm.ErrConflict
	// ErrNotFound is returned when a requested key does not exist.
	ErrNotFound = fsm.ErrNotFound
)
