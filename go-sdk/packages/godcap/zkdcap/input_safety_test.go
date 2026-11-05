package zkdcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/bincode"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/bonsai"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/pccs"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/sp1"
)

func validCollateral() *Collateral {
	return &Collateral{TcbInfo: &pccs.TcbInfo{TcbInfo: json.RawMessage(`{"id":"SGX"}`), Signature: "01"},
		QeIdentity: &pccs.EnclaveIdentityInfo{Identity: json.RawMessage(`{"id":"QE"}`), Signature: "02"},
		RootCa:     []byte{1}, TcbSigningCa: []byte{2}, RootCaCrl: []byte{3}, PckPlatformCrl: []byte{4}}
}

func TestCollateralEncodingErrorsPropagateBeforeProverRequests(t *testing.T) {
	for _, target := range []string{"tcb", "qe", "missing-tcb", "missing-qe", "nil"} {
		t.Run(target, func(t *testing.T) {
			collateral := validCollateral()
			switch target {
			case "tcb":
				collateral.TcbInfo.TcbInfo = json.RawMessage("{")
			case "qe":
				collateral.QeIdentity.Identity = json.RawMessage("{")
			case "missing-tcb":
				collateral.TcbInfo = nil
			case "missing-qe":
				collateral.QeIdentity = nil
			case "nil":
				collateral = nil
			}
			if _, err := collateral.Encode(); err == nil {
				t.Fatal("invalid collateral encoded")
			}
			if _, err := BonsaiGenerateInput(nil, collateral); err == nil {
				t.Fatal("Bonsai lost error")
			}
			if _, err := Sp1GenerateInput(nil, collateral); err == nil {
				t.Fatal("SP1 lost error")
			}
			// Uninitialized clients would panic if reached: invalid input must fail first.
			client := &ZkProofClient{Bonsai: &bonsai.Client{}, Sp1: &sp1.Client{}}
			for _, backend := range []ZkType{ZkTypeRiscZero, ZkTypeSuccinct} {
				if _, err := client.ProveQuote(context.Background(), backend, nil, collateral); err == nil {
					t.Fatal("input validation bypassed")
				}
			}
		})
	}
}

func TestCollateralAndGuestEncodingUnchanged(t *testing.T) {
	c := validCollateral()
	tcb := []byte(`{"tcbInfo":{"id":"SGX"},"signature":"01"}`)
	qe := []byte(`{"enclaveIdentity":{"id":"QE"},"signature":"02"}`)
	fields := [][]byte{tcb, qe, c.RootCa, c.TcbSigningCa, nil, c.RootCaCrl, nil, c.PckPlatformCrl}
	var expected []byte
	for _, field := range fields {
		expected = binary.LittleEndian.AppendUint32(expected, uint32(len(field)))
	}
	for _, field := range fields {
		expected = append(expected, field...)
	}
	encoded, err := c.Encode()
	if err != nil || !bytes.Equal(encoded, expected) {
		t.Fatalf("collateral wire changed: %v", err)
	}
	quote := []byte{5, 6, 7}
	input, err := encodeGuestInput(quote, c, 1234)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint64(input[:8]) != 1234 || binary.LittleEndian.Uint32(input[8:12]) != 3 ||
		int(binary.LittleEndian.Uint32(input[12:16])) != len(expected) || !bytes.Equal(input[16:], append(quote, expected...)) {
		t.Fatal("guest wire changed")
	}
}

func TestWrongBonsaiReceiptVariantReturnsError(t *testing.T) {
	for _, info := range []*bonsai.ProveInfo{nil, {}, {Receipt: &bonsai.Receipt{}},
		{Receipt: &bonsai.Receipt{Inner: bonsai.InnerReceipt{Type: 1, Succinct: &bonsai.SuccinctReceipt[*bonsai.ReceiptClaim]{}}}}} {
		if _, err := encodeBonsaiProof(info); err == nil {
			t.Fatal("non-Groth16 receipt accepted")
		}
	}
	info := &bonsai.ProveInfo{Receipt: &bonsai.Receipt{
		Inner: bonsai.InnerReceipt{Type: 2, Groth16: &bonsai.Groth16Receipt[*bonsai.ReceiptClaim]{
			Seal: bincode.Bytes{7, 8}, VerifierParameters: bonsai.Digest{0x04030201}}},
		Journal: bonsai.Journal{Bytes: bincode.Bytes{9}},
	}}
	proof, err := encodeBonsaiProof(info)
	if err != nil || !bytes.Equal(proof.Output, []byte{9}) || !bytes.Equal(proof.Proof, []byte{1, 2, 3, 4, 7, 8}) {
		t.Fatalf("valid receipt encoding changed: %v, %v", proof, err)
	}
}
