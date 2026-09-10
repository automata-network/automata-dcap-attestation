package parser

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func vectorV2(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../../evm/forge-test/assets/v2/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestOutputV2SharedVectors(t *testing.T) {
	for _, name := range []string{"sgx-empty", "tdx10-advisories", "tdx15-relaunch"} {
		data := vectorV2(t, name)
		out, err := ParseOutputV2(data)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := out.MarshalBinary()
		if err != nil || !bytes.Equal(data, encoded) {
			t.Fatalf("roundtrip %s: %v", name, err)
		}
		if out.Timestamp != 0x0102030405060708 || out.PPID != [16]byte{} {
			t.Fatal("incorrect header offsets")
		}
		for size := 0; size < 289+len(out.QuoteBody); size++ {
			if _, err := ParseOutputV2(data[:size]); err == nil {
				t.Fatalf("accepted truncation %d", size)
			}
		}
	}
}
func TestOutputV2RejectsMutations(t *testing.T) {
	data := vectorV2(t, "sgx-empty")
	for offset, value := range map[int]byte{0: 1, 3: 2, 4: 0, 9: 10, 48: 2, 32: 1, 49: 0, 51: 0, 53: 1, 56: 1} {
		bad := append([]byte(nil), data...)
		bad[offset] = value
		if _, err := ParseOutputV2(bad); err == nil {
			t.Fatalf("accepted mutation %d", offset)
		}
	}
	if _, err := ParseOutputV2(append(data, 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}
func FuzzOutputV2Parser(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 289))
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := ParseOutputV2(data)
		if err == nil {
			b, err := out.MarshalBinary()
			if err != nil || !bytes.Equal(data, b) {
				t.Fatal("noncanonical parse")
			}
		}
	})
}
