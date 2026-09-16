package feev2

import (
	"bytes"
	"context"
	"encoding/hex"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"os"
	"strings"
	"testing"
)

type callerMock struct {
	bind.ContractBackend
	call func(ethereum.CallMsg) ([]byte, error)
}

func (m *callerMock) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return []byte{1}, nil
}
func (m *callerMock) CallContract(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	return m.call(msg)
}
func wire(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../../evm/forge-test/assets/v2/sgx-empty.hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestV2SelectorsAndVerbatimJournal(t *testing.T) {
	backend := new(callerMock)
	client, err := New(common.HexToAddress("0x1234"), backend)
	if err != nil {
		t.Fatal(err)
	}
	journal := wire(t)
	id := [32]byte{1}
	minCheck := false
	backend.call = func(msg ethereum.CallMsg) ([]byte, error) {
		method, err := client.abi.MethodById(msg.Data[:4])
		if err != nil {
			t.Fatal(err)
		}
		if method.Sig != "verifyAndAttestWithZKProofV2(bytes,uint8,bytes,bytes32,uint32,bool)" {
			t.Fatal(method.Sig)
		}
		args, err := method.Inputs.Unpack(msg.Data[4:])
		if err != nil {
			t.Fatal(err)
		}
		if args[3].([32]byte) != id || args[4].(uint32) != 17 || args[5].(bool) != minCheck {
			t.Fatal("ID/evaluation number/minCheck discarded")
		}
		return method.Outputs.Pack(true, journal)
	}
	output, err := client.VerifyAndAttestWithZKProofV2(nil, journal, 1, []byte{0, 0, 0, 0}, &id, 17, false)
	if err != nil || !bytes.Equal(output, journal) {
		t.Fatalf("verification: %v", err)
	}
	minCheck = true
	output, err = client.VerifyAndAttestWithZKProofV2(nil, journal, 1, []byte{0, 0, 0, 0}, &id, 17, minCheck)
	if err != nil || !bytes.Equal(output, journal) {
		t.Fatalf("minimal verification: %v", err)
	}
}

func TestRawV2ModeAndDefaultSelectors(t *testing.T) {
	backend := new(callerMock)
	client, err := New(common.HexToAddress("0x1234"), backend)
	if err != nil {
		t.Fatal(err)
	}
	for _, minCheck := range []bool{false, true} {
		backend.call = func(msg ethereum.CallMsg) ([]byte, error) {
			method, err := client.abi.MethodById(msg.Data[:4])
			if err != nil {
				t.Fatal(err)
			}
			if method.Sig != "verifyAndAttestOnChainV2(bytes,uint32,bool)" {
				t.Fatal(method.Sig)
			}
			args, err := method.Inputs.Unpack(msg.Data[4:])
			if err != nil {
				t.Fatal(err)
			}
			if args[1].(uint32) != 17 || args[2].(bool) != minCheck {
				t.Fatal("mode/evaluation discarded")
			}
			return method.Outputs.Pack(true, wire(t))
		}
		if _, err := client.VerifyAndAttestOnChainV2(nil, []byte{1}, 17, minCheck); err != nil {
			t.Fatal(err)
		}
	}
	backend.call = func(msg ethereum.CallMsg) ([]byte, error) {
		method, err := client.abi.MethodById(msg.Data[:4])
		if err != nil {
			t.Fatal(err)
		}
		if method.Sig != "verifyAndAttestOnChainV2(bytes)" && method.Sig != "verifyAndAttestWithZKProofV2(bytes,uint8,bytes)" {
			t.Fatal(method.Sig)
		}
		return method.Outputs.Pack(true, wire(t))
	}
	if _, err := client.VerifyAndAttestOnChainV2Default(nil, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyAndAttestWithZKProofV2Default(nil, wire(t), 1, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultUsesV2ProgramID(t *testing.T) {
	backend := new(callerMock)
	client, _ := New(common.HexToAddress("0x1234"), backend)
	journal := wire(t)
	calls := 0
	backend.call = func(msg ethereum.CallMsg) ([]byte, error) {
		method, err := client.abi.MethodById(msg.Data[:4])
		if err != nil {
			t.Fatal(err)
		}
		calls++
		if calls == 1 {
			if method.Sig != "programIdentifierV2(uint8)" {
				t.Fatal(method.Sig)
			}
			return method.Outputs.Pack([32]byte{9})
		}
		return method.Outputs.Pack(true, journal)
	}
	if _, err := client.VerifyAndAttestWithZKProofV2(nil, journal, 1, make([]byte, 4), nil, 0, false); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}

func TestV2EventVersions(t *testing.T) {
	client, _ := New(common.HexToAddress("0x1234"), new(callerMock))
	event := client.abi.Events["AttestationSubmittedV2"]
	data, err := event.Inputs.NonIndexed().Pack(true, uint8(1), wire(t))
	if err != nil {
		t.Fatal(err)
	}
	log := types.Log{Topics: []common.Hash{event.ID, common.BigToHash(big.NewInt(2)), common.BigToHash(big.NewInt(1))}, Data: data}
	parsed, err := client.ParseAttestationSubmittedV2(log)
	if err != nil || parsed.FormatMajorVersion != 2 {
		t.Fatalf("event: %v", err)
	}
	log.Topics[2] = common.BigToHash(big.NewInt(2))
	if _, err := client.ParseAttestationSubmittedV2(log); err == nil {
		t.Fatal("accepted unknown minor version")
	}
}
