package zkdcap

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/parser"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/pccs"
	"github.com/ethereum/go-ethereum/accounts/abi"
)

// GenerateInputV2 encodes the shared RISC Zero/SP1/Pico V2 guest ABI:
// (bytes collateral, bytes quote, uint64 verificationTimestamp). This is only
// input preparation, not cryptographic validation or remote proof generation.
// Legacy BonsaiGenerateInput and Sp1GenerateInput retain their existing format.
func GenerateInputV2(quote []byte, collateral *Collateral, verificationTimestamp uint64) ([]byte, error) {
	q, err := parser.NewQuoteParserSafe(quote)
	if err != nil {
		return nil, err
	}
	// Legacy parsing accepts transport padding. V2 must not trim or accept it.
	certData, err := q.CertData()
	if err != nil {
		return nil, err
	}
	certStart, err := q.CertDataOffset()
	if err != nil {
		return nil, err
	}
	prefix := 576
	if binary.LittleEndian.Uint16(quote[:2]) != parser.V3_QUOTE {
		prefix = 582
	}
	authStart := q.Spec().AuthDataSizeOffset() - prefix
	if certStart+len(certData) != len(quote) ||
		uint64(authStart)+uint64(binary.LittleEndian.Uint32(quote[authStart-4:authStart])) != uint64(len(quote)) {
		return nil, fmt.Errorf("V2 requires an exact quote frame without trailing bytes")
	}
	if prefix == 582 && uint64(authStart+134)+uint64(binary.LittleEndian.Uint32(quote[authStart+130:authStart+134])) != uint64(len(quote)) {
		return nil, fmt.Errorf("V2 requires an exact QE report certification frame")
	}
	if collateral == nil || len(collateral.RootCa) == 0 || len(collateral.TcbSigningCa) == 0 || len(collateral.RootCaCrl) == 0 {
		return nil, fmt.Errorf("missing V2 collateral certificates or root CRL")
	}
	certs, err := q.Certificates()
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("missing PCK certificate")
	}
	ca, err := q.PckType(certs[0])
	if err != nil {
		return nil, err
	}
	pckCRL := collateral.PckProcessorCrl
	if ca == pccs.CA_PLATFORM {
		pckCRL = collateral.PckPlatformCrl
	}
	if len(pckCRL) == 0 {
		return nil, fmt.Errorf("missing PCK CRL for quote issuer")
	}
	tcb, err := collateral.TcbInfo.Encode()
	if err != nil {
		return nil, err
	}
	qe, err := collateral.QeIdentity.Encode()
	if err != nil {
		return nil, err
	}
	var tcbVersion, qeVersion struct {
		Version uint32 `json:"version"`
	}
	if err = json.Unmarshal(collateral.TcbInfo.TcbInfo, &tcbVersion); err != nil || tcbVersion.Version != 3 {
		return nil, fmt.Errorf("V2 requires TCB Info v3")
	}
	if err = json.Unmarshal(collateral.QeIdentity.Identity, &qeVersion); err != nil || qeVersion.Version != 2 {
		return nil, fmt.Errorf("V2 requires QE Identity v2 from PCS API v4")
	}
	collateralABI, err := v2Arguments("bytes", "bytes", "bytes[2]", "string", "string")
	if err != nil {
		return nil, err
	}
	encoded, err := collateralABI.Pack(collateral.RootCaCrl, pckCRL,
		[2][]byte{collateral.TcbSigningCa, collateral.RootCa}, string(tcb), string(qe))
	if err != nil {
		return nil, err
	}
	inputABI, err := v2Arguments("bytes", "bytes", "uint64")
	if err != nil {
		return nil, err
	}
	return inputABI.Pack(encoded, quote, verificationTimestamp)
}

func v2Arguments(names ...string) (abi.Arguments, error) {
	args := make(abi.Arguments, len(names))
	for i, name := range names {
		typ, err := abi.NewType(name, "", nil)
		if err != nil {
			return nil, err
		}
		args[i] = abi.Argument{Type: typ}
	}
	return args, nil
}
