package sp1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/bincode"
	"github.com/ethereum/go-ethereum/common"
)

// SDK 6.8.0 uses circuit v6.1.0, not a circuit named v6.8.0.
const V6CircuitVersion = "v6.1.0"
const v6VerifierHash = "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"
const v6VkRoot = "002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352"

// decodeNetworkProof consumes upstream ProofFromNetwork, not the local SDK's
// optional-TEE container. Never guess a bincode schema from untrusted payloads.
func decodeNetworkProof(data []byte, circuit string) (*SP1ProofWithPublicValues, error) {
	if circuit != V6CircuitVersion {
		return bincode.Unmarshal[*SP1ProofWithPublicValues](data)
	}
	p := &SP1ProofWithPublicValues{}
	remaining, err := p.Proof.Type.FromBin(data)
	if err != nil || p.Proof.Type.Raw() != 3 {
		return nil, fmt.Errorf("SP1 v6 network response must be Groth16: %v", err)
	}
	g := &Groth16Bn254Proof{}
	p.Proof.Groth16 = g
	fields := []bincode.FromBin{&g.PublicInputs[0], &g.PublicInputs[1],
		&g.AdditionalPublicInputs[0], &g.AdditionalPublicInputs[1], &g.AdditionalPublicInputs[2],
		&g.EncodedProof, &g.RawProof, &g.Groth16VkeyHash, &p.PublicValues, &p.Sp1Version}
	remaining, err = bincode.UnmarshalFields(remaining, fields)
	if err != nil {
		return nil, err
	}
	if len(remaining) != 0 || string(p.Sp1Version) != V6CircuitVersion {
		return nil, fmt.Errorf("SP1 v6 response has trailing bytes or wrong circuit version")
	}
	if _, err := p.v6Bytes(); err != nil {
		return nil, err
	}
	return p, nil
}

func decimalWord(value bincode.String) ([]byte, error) {
	n, ok := new(big.Int).SetString(string(value), 10)
	if !ok || n.Sign() < 0 || n.BitLen() > 256 {
		return nil, fmt.Errorf("invalid SP1 v6 public input")
	}
	return n.FillBytes(make([]byte, 32)), nil
}

// v6Bytes validates framing/metadata, NOT the Groth16 pairing. Callers must
// verify via a trusted SDK or on-chain verifier before trusting public values.
func (p *SP1ProofWithPublicValues) v6Bytes() ([]byte, error) {
	if p == nil || string(p.Sp1Version) != V6CircuitVersion || p.Proof.Type.Raw() != 3 || p.Proof.Groth16 == nil {
		return nil, fmt.Errorf("expected an SP1 v6.1.0 Groth16 proof")
	}
	g := p.Proof.Groth16
	if hex.EncodeToString(g.Groth16VkeyHash[:]) != v6VerifierHash {
		return nil, fmt.Errorf("SP1 v6 verifier hash mismatch")
	}
	proof, err := hex.DecodeString(string(g.EncodedProof))
	if err != nil || len(proof) != 352 {
		return nil, fmt.Errorf("SP1 v6 Groth16 payload must be 352 bytes")
	}
	for i, input := range g.AdditionalPublicInputs {
		word, err := decimalWord(input)
		if err != nil || !bytes.Equal(word, proof[i*32:(i+1)*32]) {
			return nil, fmt.Errorf("SP1 v6 encoded public input mismatch at %d", i+2)
		}
	}
	if !bytes.Equal(proof[:32], make([]byte, 32)) || hex.EncodeToString(proof[32:64]) != v6VkRoot {
		return nil, fmt.Errorf("SP1 v6 failed guest exit or incorrect recursion root")
	}
	digest := sha256.Sum256([]byte(p.PublicValues.Buffer.Data))
	digest[0] &= 0x1f // SP1's BN254 public-values commitment, not OutputV2 hashes.
	word, err := decimalWord(g.PublicInputs[1])
	if err != nil || !bytes.Equal(word, digest[:]) {
		return nil, fmt.Errorf("SP1 v6 public-values commitment mismatch")
	}
	return append(append([]byte{}, g.Groth16VkeyHash[:4]...), proof...), nil
}

// ValidateV6PublicInputs binds the returned metadata to the requested native ID.
// It is not cryptographic proof verification. In particular, an attacker can
// recompute these commitments; a trusted verifier must still check the proof.
func (p *SP1ProofWithPublicValues) ValidateV6PublicInputs(expected common.Hash) error {
	if _, err := p.v6Bytes(); err != nil {
		return err
	}
	word, err := decimalWord(p.Proof.Groth16.PublicInputs[0])
	if err != nil || !bytes.Equal(word, expected[:]) || expected == (common.Hash{}) {
		return fmt.Errorf("SP1 v6 program identifier mismatch")
	}
	return nil
}
