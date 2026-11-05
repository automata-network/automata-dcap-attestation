package pccs

import (
	"encoding/json"
	"testing"
)

func TestEncodePropagatesInvalidRawJSON(t *testing.T) {
	for _, raw := range []string{"{", "not-json", "[1,]"} {
		if _, err := (&TcbInfo{TcbInfo: json.RawMessage(raw)}).Encode(); err == nil {
			t.Fatal("invalid TCB JSON encoded")
		}
		if _, err := (&EnclaveIdentityInfo{Identity: json.RawMessage(raw)}).Encode(); err == nil {
			t.Fatal("invalid identity JSON encoded")
		}
	}
	for _, raw := range []string{`{}`, `{"id":"SGX","advisoryIDs":["A","A"]}`} {
		original := &TcbInfo{TcbInfo: json.RawMessage(raw), Signature: "0011"}
		data, err := original.Encode()
		if err != nil {
			t.Fatal(err)
		}
		var decoded TcbInfo
		if err := json.Unmarshal(data, &decoded); err != nil || string(decoded.TcbInfo) != raw || decoded.Signature != original.Signature {
			t.Fatalf("valid encoding changed: %v", err)
		}
	}
}
