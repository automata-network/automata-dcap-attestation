// Package feev2 calls the identity-bearing entrypoint directly, without DcapPortal.
package feev2

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/parser"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// ABI is generated from the FeeV2 artifact, restricted to application-facing methods/events.
//
//go:embed abi.json
var ABI string

type Client struct {
	contract *bind.BoundContract
	abi      abi.ABI
}

func New(address common.Address, backend bind.ContractBackend) (*Client, error) {
	if address == (common.Address{}) {
		return nil, fmt.Errorf("FeeV2 address is required")
	}
	parsed, err := abi.JSON(strings.NewReader(ABI))
	if err != nil {
		return nil, err
	}
	return &Client{bind.NewBoundContract(address, parsed, backend, backend, backend), parsed}, nil
}

func (c *Client) method(signature string) (string, error) {
	for name, method := range c.abi.Methods {
		if method.Sig == signature {
			return name, nil
		}
	}
	return "", fmt.Errorf("FeeV2 ABI missing %s", signature)
}

func (c *Client) call(opts *bind.CallOpts, signature string, args ...interface{}) ([]interface{}, error) {
	name, err := c.method(signature)
	if err != nil {
		return nil, err
	}
	var result []interface{}
	err = c.contract.Call(opts, &result, name, args...)
	return result, err
}

func verificationOutput(result []interface{}, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	if len(result) != 2 {
		return nil, fmt.Errorf("invalid FeeV2 return arity")
	}
	success, ok := result[0].(bool)
	if !ok {
		return nil, fmt.Errorf("invalid FeeV2 success value")
	}
	output, ok := result[1].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid FeeV2 output value")
	}
	if !success {
		return nil, fmt.Errorf("DCAP V2 verification failed: %s", output)
	}
	if _, err = parser.ParseOutputV2(output); err != nil {
		return nil, err
	}
	return output, nil
}

func (c *Client) VerifyAndAttestOnChainV2(opts *bind.CallOpts, quote []byte, tcbEval uint32) ([]byte, error) {
	return verificationOutput(c.call(opts, "verifyAndAttestOnChainV2(bytes,uint32)", quote, tcbEval))
}

func (c *Client) VerifyAndAttestOnChainV2Default(opts *bind.CallOpts, quote []byte) ([]byte, error) {
	return verificationOutput(c.call(opts, "verifyAndAttestOnChainV2(bytes)", quote))
}

func (c *Client) ProgramIdentifierV2(opts *bind.CallOpts, backend uint8) ([32]byte, error) {
	result, err := c.call(opts, "programIdentifierV2(uint8)", backend)
	if err != nil {
		return [32]byte{}, err
	}
	if len(result) != 1 {
		return [32]byte{}, fmt.Errorf("invalid program ID result")
	}
	id, ok := result[0].([32]byte)
	if !ok {
		return id, fmt.Errorf("invalid program ID type")
	}
	return id, nil
}

func (c *Client) VerifyAndAttestWithZKProofV2(opts *bind.CallOpts, journal []byte, backend uint8, proof []byte, id *[32]byte, tcbEval uint32) ([]byte, error) {
	if _, err := parser.ParseOutputV2(journal); err != nil {
		return nil, err
	}
	if backend < 1 || backend > 3 {
		return nil, fmt.Errorf("invalid ZK backend")
	}
	var program [32]byte
	if id == nil {
		var err error
		program, err = c.ProgramIdentifierV2(opts, backend)
		if err != nil {
			return nil, err
		}
	} else {
		program = *id
	}
	output, err := verificationOutput(c.call(opts, "verifyAndAttestWithZKProofV2(bytes,uint8,bytes,bytes32,uint32)", journal, backend, proof, program, tcbEval))
	if err == nil && !bytes.Equal(output, journal) {
		return nil, fmt.Errorf("returned bytes differ from proven journal")
	}
	return output, err
}

func (c *Client) VerifyAndAttestWithZKProofV2Default(opts *bind.CallOpts, journal []byte, backend uint8, proof []byte) ([]byte, error) {
	if _, err := parser.ParseOutputV2(journal); err != nil {
		return nil, err
	}
	output, err := verificationOutput(c.call(opts, "verifyAndAttestWithZKProofV2(bytes,uint8,bytes)", journal, backend, proof))
	if err == nil && !bytes.Equal(output, journal) {
		return nil, fmt.Errorf("returned bytes differ from proven journal")
	}
	return output, err
}

// TransactOnChainV2 sends a transaction only when explicitly called with signing options.
func (c *Client) TransactOnChainV2(opts *bind.TransactOpts, quote []byte, tcbEval uint32) (*types.Transaction, error) {
	name, err := c.method("verifyAndAttestOnChainV2(bytes,uint32)")
	if err != nil {
		return nil, err
	}
	return c.contract.Transact(opts, name, quote, tcbEval)
}

type AttestationSubmittedV2 struct {
	Success            bool
	VerifierType       uint8
	FormatMajorVersion uint16
	FormatMinorVersion uint16
	Output             []byte
	Raw                types.Log
}

func (c *Client) ParseAttestationSubmittedV2(log types.Log) (*AttestationSubmittedV2, error) {
	event := new(AttestationSubmittedV2)
	if err := c.contract.UnpackLog(event, "AttestationSubmittedV2", log); err != nil {
		return nil, err
	}
	if event.FormatMajorVersion != 2 || event.FormatMinorVersion != 1 {
		return nil, fmt.Errorf("unsupported output schema in event")
	}
	if event.Success {
		if _, err := parser.ParseOutputV2(event.Output); err != nil {
			return nil, err
		}
	}
	event.Raw = log
	return event, nil
}
