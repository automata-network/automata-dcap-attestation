package sp1

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/chzyer/logex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

var EIP712DomainName = "EIP712Domain"
var EIP712Domain = apitypes.TypedDataDomain{
	Name:    "succinct",
	Version: "1",
}
var EIP712DomainType = []apitypes.Type{
	{Name: "name", Type: "string"},
	{Name: "version", Type: "string"},
}

type CreateProofMsg struct {
	Nonce    uint64
	Deadline uint64
	Mode     uint32
	Version  string
}

func (c *CreateProofMsg) EIP712Type() (string, []apitypes.Type) {
	return "CreateProof", []apitypes.Type{
		{Name: "nonce", Type: "uint64"},
		{Name: "deadline", Type: "uint64"},
		{Name: "mode", Type: "uint32"},
		{Name: "version", Type: "string"},
	}
}

func (c *CreateProofMsg) EIP712Data() apitypes.TypedDataMessage {
	return map[string]interface{}{
		"nonce":    new(big.Int).SetUint64(c.Nonce),
		"deadline": new(big.Int).SetUint64(c.Deadline),
		"mode":     big.NewInt(int64(c.Mode)),
		"version":  c.Version,
	}
}

type SubmitProofMsg struct {
	Nonce   uint64
	ProofId string
}

func (c *SubmitProofMsg) EIP712Type() (string, []apitypes.Type) {
	return "SubmitProof", []apitypes.Type{
		{Name: "nonce", Type: "uint64"},
		{Name: "proof_id", Type: "string"},
	}
}

func (c *SubmitProofMsg) EIP712Data() apitypes.TypedDataMessage {
	return map[string]interface{}{
		"nonce":    new(big.Int).SetUint64(c.Nonce),
		"proof_id": c.ProofId,
	}
}

type TypedData interface {
	EIP712Type() (string, []apitypes.Type)
	EIP712Data() apitypes.TypedDataMessage
}

type EIP712Auth struct {
	key *ecdsa.PrivateKey
}

func NewEIP712Auth(key *ecdsa.PrivateKey) *EIP712Auth {
	return &EIP712Auth{key: key}
}

func (a *EIP712Auth) SignMessage(msg TypedData) ([]byte, error) {
	msgTypeName, msgType := msg.EIP712Type()
	typedData := &apitypes.TypedData{
		Types: apitypes.Types{
			EIP712DomainName: EIP712DomainType,
			msgTypeName:      msgType,
		},
		PrimaryType: msgTypeName,
		Domain:      EIP712Domain,
		Message:     msg.EIP712Data(),
	}
	messageHash, err := a.SigningHash(typedData)
	if err != nil {
		return nil, logex.Trace(err)
	}
	sig, err := crypto.Sign(messageHash[:], a.key)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return sig, nil
}

func (a *EIP712Auth) SigningHash(typedData *apitypes.TypedData) (common.Hash, error) {
	var sighash common.Hash
	domainSeparator, err := typedData.HashStruct(EIP712DomainName, typedData.Domain.Map())
	if err != nil {
		return sighash, logex.Trace(err)
	}

	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return sighash, logex.Trace(err)
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	copy(sighash[:], crypto.Keccak256(rawData))

	return sighash, nil
}

func EIP191SignHashMsg(data []byte) common.Hash {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}

func EIP191SignHash(prvKey *ecdsa.PrivateKey, data []byte) (sig []byte, err error) {
	msg := EIP191SignHashMsg(data)
	return crypto.Sign(msg[:], prvKey)
}
