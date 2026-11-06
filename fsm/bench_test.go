package fsm

import (
	"bytes"
	"testing"

	hraft "github.com/hashicorp/raft"
)

func BenchmarkEnvelopeApply(b *testing.B) {
	inner := NewMemoryKVFSM(nil)
	env := NewEnvelopeFSM(inner, nil, nil, nil)
	value := bytes.Repeat([]byte("x"), 1024)
	data, err := (CommandCodec{}).Encode(KindSet, KVEntry{Bucket: "bench", Key: "key", Value: value})
	if err != nil {
		b.Fatal(err)
	}
	log := &hraft.Log{Data: data}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if resp := env.Apply(log); resp != nil {
			b.Fatalf("apply: %v", resp)
		}
	}
}

func BenchmarkMemoryKVFSMApply(b *testing.B) {
	kv := NewMemoryKVFSM(nil)
	value := bytes.Repeat([]byte("x"), 1024)
	data, err := (CommandCodec{}).Encode(KindSet, KVEntry{Bucket: "bench", Key: "key", Value: value})
	if err != nil {
		b.Fatal(err)
	}
	log := &hraft.Log{Data: data}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if resp := kv.Apply(log); resp != nil {
			b.Fatalf("apply: %v", resp)
		}
	}
}
