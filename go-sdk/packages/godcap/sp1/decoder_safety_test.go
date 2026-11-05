package sp1

import (
	"encoding/hex"
	"testing"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/bincode"
)

func TestSP1DecoderRejectsTruncationAndLegacyEnvelope(t *testing.T) {
	data := currentProofFixture(t)
	for n := 0; n < len(data); n++ {
		if _, err := bincode.Unmarshal[*SP1ProofWithPublicValues](data[:n]); err == nil {
			t.Fatalf("accepted prefix %d", n)
		}
	}
	if _, err := bincode.Unmarshal[*SP1ProofWithPublicValues](append(data, 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	legacy, err := hex.DecodeString(testProof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bincode.Unmarshal[*SP1ProofWithPublicValues](legacy); err == nil {
		t.Fatal("legacy stdin envelope interpreted as current format")
	}
}

func FuzzSP1ProofDecoder(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{3, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255})
	f.Add(currentProofFixture(f))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = bincode.Unmarshal[*SP1ProofWithPublicValues](data) })
}
