package sp1

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/bincode"
	"github.com/ethereum/go-ethereum/common"
)

// Synthetic encoding fixture only: zero curve points are NOT a valid proof.
func v6EncodingFixture() (*SP1ProofWithPublicValues, common.Hash) {
	id := common.HexToHash("0x1234")
	journal := []byte("compact journal codec test, not verified attestation")
	digest := sha256.Sum256(journal)
	digest[0] &= 0x1f
	root, _ := hex.DecodeString(v6VkRoot)
	hash, _ := hex.DecodeString(v6VerifierHash)
	proof := make([]byte, 352)
	copy(proof[32:64], root)
	proof[95] = 7
	g := &Groth16Bn254Proof{
		PublicInputs:           [2]bincode.String{bincode.String(new(big.Int).SetBytes(id[:]).String()), bincode.String(new(big.Int).SetBytes(digest[:]).String())},
		AdditionalPublicInputs: [3]bincode.String{"0", bincode.String(new(big.Int).SetBytes(root).String()), "7"},
		EncodedProof:           bincode.String(hex.EncodeToString(proof)), RawProof: "",
	}
	copy(g.Groth16VkeyHash[:], hash)
	return &SP1ProofWithPublicValues{Proof: SP1Proof{Type: 3, Groth16: g},
		PublicValues: SP1PublicValues{Buffer: Buffer{Data: bincode.Bytes(journal)}}, Sp1Version: V6CircuitVersion}, id
}

func encodeV6NetworkFixture(p *SP1ProofWithPublicValues) []byte {
	g := p.Proof.Groth16
	out := binary.LittleEndian.AppendUint32(nil, 3)
	put := func(s []byte) { out = binary.LittleEndian.AppendUint64(out, uint64(len(s))); out = append(out, s...) }
	for _, s := range g.PublicInputs {
		put([]byte(s))
	}
	for _, s := range g.AdditionalPublicInputs {
		put([]byte(s))
	}
	put([]byte(g.EncodedProof))
	put([]byte(g.RawProof))
	out = append(out, g.Groth16VkeyHash[:]...)
	put([]byte(p.PublicValues.Buffer.Data))
	put([]byte(p.Sp1Version))
	return out
}

func TestV6NetworkEncodingAndCalldata(t *testing.T) {
	p, id := v6EncodingFixture()
	decoded, err := decodeNetworkProof(encodeV6NetworkFixture(p), V6CircuitVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.ValidateV6PublicInputs(id); err != nil {
		t.Fatal(err)
	}
	encoded, err := decoded.Bytes()
	if err != nil || len(encoded) != 356 || hex.EncodeToString(encoded[:4]) != "4388a21c" {
		t.Fatalf("bad v6 calldata: %v", err)
	}
	if err := decoded.ValidateV6PublicInputs(common.HexToHash("0x9999")); err == nil {
		t.Fatal("accepted wrong program ID")
	}
	// Legacy default decoder must not guess v6's extra public inputs.
	if _, err := decodeNetworkProof(encodeV6NetworkFixture(p), "v5.2.1"); err == nil {
		t.Fatal("v6 decoded as legacy")
	}
}

func TestV6RejectMalformedNetworkProofs(t *testing.T) {
	p, _ := v6EncodingFixture()
	encoded := encodeV6NetworkFixture(p)
	for i := 0; i < len(encoded); i++ {
		if _, err := decodeNetworkProof(encoded[:i], V6CircuitVersion); err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	if _, err := decodeNetworkProof(append(encoded, 0), V6CircuitVersion); err == nil {
		t.Fatal("accepted local SDK TEE field as network wire")
	}
	for name, mutate := range map[string]func(*SP1ProofWithPublicValues){
		"version": func(p *SP1ProofWithPublicValues) { p.Sp1Version = "v5.2.1" },
		"hash":    func(p *SP1ProofWithPublicValues) { p.Proof.Groth16.Groth16VkeyHash[0] ^= 1 },
		"journal": func(p *SP1ProofWithPublicValues) { p.PublicValues.Buffer.Data[0] ^= 1 },
		"length": func(p *SP1ProofWithPublicValues) {
			p.Proof.Groth16.EncodedProof = bincode.String(strings.Repeat("00", 256))
		},
		"exit":     func(p *SP1ProofWithPublicValues) { p.Proof.Groth16.AdditionalPublicInputs[0] = "1" },
		"root":     func(p *SP1ProofWithPublicValues) { p.Proof.Groth16.AdditionalPublicInputs[1] = "1" },
		"nonce":    func(p *SP1ProofWithPublicValues) { p.Proof.Groth16.AdditionalPublicInputs[2] = "8" },
		"negative": func(p *SP1ProofWithPublicValues) { p.Proof.Groth16.PublicInputs[1] = "-1" },
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := v6EncodingFixture()
			mutate(p)
			if _, err := decodeNetworkProof(encodeV6NetworkFixture(p), V6CircuitVersion); err == nil {
				t.Fatal("accepted mutation")
			}
		})
	}
}

func TestV6CircuitIsNotSdkVersionAndLegacyDefaultIsPreserved(t *testing.T) {
	legacy := &Config{}
	if err := legacy.Init(); err != nil || legacy.Version != "v5.2.1" {
		t.Fatal("legacy defaults changed")
	}
	for _, version := range []string{"v6.0.0", "v6.8.0"} {
		if err := (&Config{Version: version}).Init(); err == nil {
			t.Fatal("accepted unsupported circuit")
		}
	}
	if err := (&Config{Version: V6CircuitVersion}).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewV6Client(nil); err == nil {
		t.Fatal("accepted nil config")
	}
	if _, err := NewV6Client(&Config{Version: "v5.2.1"}); err == nil {
		t.Fatal("accepted legacy as v6")
	}
}
