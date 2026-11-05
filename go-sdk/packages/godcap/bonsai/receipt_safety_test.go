package bonsai

import (
	"encoding/hex"
	"testing"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/bincode"
)

func TestReceiptMalformedFieldsReturnErrors(t *testing.T) {
	if _, err := new(ExitCode).FromBin([]byte{255, 0, 0, 0}); err == nil {
		t.Fatal("invalid exit code accepted")
	}
	if _, err := new(Digest).FromBin(make([]byte, 31)); err == nil {
		t.Fatal("short digest accepted")
	}
	var input MaybePruned[*bincode.Option[*Input]]
	if _, err := input.FromBin([]byte{0, 0, 0, 0, 1}); err == nil {
		t.Fatal("unsupported unpruned input accepted")
	}
}

func TestReceiptTruncation(t *testing.T) {
	for _, encoded := range []string{testReceipt1, testReceipt2} {
		data, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewReceiptFromBincode(data); err != nil {
			t.Fatal(err)
		}
		for n := 0; n < len(data); n++ {
			// Exhaust all short-fixture prefixes; sample the 225 KB STARK fixture.
			if len(data) > 10000 && n > 128 && n < len(data)-64 && n%2048 != 0 {
				continue
			}
			if _, err := NewReceiptFromBincode(data[:n]); err == nil {
				t.Fatalf("accepted prefix %d/%d", n, len(data))
			}
		}
		if _, err := NewReceiptFromBincode(append(data, 0)); err == nil {
			t.Fatal("trailing bytes accepted")
		}
	}
}

func FuzzReceiptDecoder(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{255, 255, 255, 255})
	data, _ := hex.DecodeString(testReceipt2)
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = NewReceiptFromBincode(data) })
}
