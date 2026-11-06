package keyring

import (
	"encoding/json"
	"testing"
)

func FuzzKeyringJSON(f *testing.F) {
	f.Add([]byte(`{"keys":[],"active_key_id":"","term":1}`))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var kr TLSKeyring
		if err := json.Unmarshal(data, &kr); err != nil {
			return
		}
		_ = kr.Validate()
		_ = kr.Clone()
		_ = kr.GetActive()
	})
}
