package fsm

import "testing"

func FuzzCommandDecode(f *testing.F) {
	f.Add([]byte(`{"kind":1,"payload":{"key":"a"}}`))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = (CommandCodec{}).Decode(data)
	})
}
