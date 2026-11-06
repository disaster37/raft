package testutil

import (
	"testing"
	"time"
)

func TestFreeListener(t *testing.T) {
	ln := FreeListener(t)
	if ln == nil {
		t.Fatal("nil listener")
	}
	addr := FreeAddrFromListener(t, ln)
	if addr == "" {
		t.Fatal("empty addr")
	}
}

func TestFakeClock(t *testing.T) {
	start := time.Unix(100, 0)
	clock := NewFakeClock(start)
	if !clock.Now().Equal(start) {
		t.Fatalf("now = %v", clock.Now())
	}
	clock.Advance(time.Hour)
	if !clock.Now().Equal(start.Add(time.Hour)) {
		t.Fatalf("now = %v", clock.Now())
	}
	clock.Set(start)
	if !clock.Now().Equal(start) {
		t.Fatalf("now = %v", clock.Now())
	}
}

func TestTestCluster(t *testing.T) {
	cluster := NewTestCluster(t, 3, false)
	if cluster.Leader() == nil {
		t.Fatal("expected a leader")
	}
	if len(cluster.Nodes) != 3 || len(cluster.Addrs) != 3 {
		t.Fatalf("cluster = %+v", cluster)
	}
	cluster.Close()
}
