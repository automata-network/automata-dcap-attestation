package zkdcap

import (
	"context"
	"encoding/binary"
	"math"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/parser"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/pccs"
	"github.com/chzyer/logex"
)

type Collateral struct {
	TcbInfo         *pccs.TcbInfo
	QeIdentity      *pccs.EnclaveIdentityInfo
	RootCa          []byte
	TcbSigningCa    []byte
	PckCertChain    []byte
	RootCaCrl       []byte
	PckProcessorCrl []byte
	PckPlatformCrl  []byte
}

func NewCollateralFromQuoteParser(ctx context.Context, parser *parser.QuoteParser, ps *pccs.Client) (*Collateral, error) {
	return newCollateralFromQuoteParser(ctx, parser, ps, false, nil)
}

// NewCollateralV2FromQuoteParser selects PCS API v4 / TCB Info v3 for every
// quote version. A nil evaluation resolves the standard once for both documents.
// The returned collateral is not authenticated until verified by the V2 guest.
func NewCollateralV2FromQuoteParser(ctx context.Context, quoteParser *parser.QuoteParser, ps *pccs.Client, evaluation *uint32) (*Collateral, error) {
	if quoteParser == nil {
		return nil, logex.NewError("missing quote parser")
	}
	if ps == nil {
		return nil, logex.NewError("missing PCCS client")
	}
	// Re-detect the quote spec: the original caller may still own the byte slice.
	current, err := parser.NewQuoteParserSafe(quoteParser.Quote())
	if err != nil {
		return nil, err
	}
	return newCollateralFromQuoteParser(ctx, current, ps, true, evaluation)
}

func newCollateralFromQuoteParser(ctx context.Context, parser *parser.QuoteParser, ps *pccs.Client, v2 bool, evaluation *uint32) (*Collateral, error) {
	if parser == nil {
		return nil, logex.NewError("missing quote parser")
	}
	certs, err := parser.Certificates()
	if err != nil {
		return nil, logex.Trace(err)
	}
	if len(certs) == 0 {
		return nil, logex.NewError("quote contains no PCK certificates")
	}
	pckType, err := parser.PckType(certs[0])
	if err != nil {
		return nil, logex.Trace(err)
	}
	sgxExts, err := parser.SgxExt(certs[0])
	if err != nil {
		return nil, logex.Trace(err)
	}
	fmpsc := parser.Fmpsc(sgxExts)

	rootCert, err := ps.GetCertByID(ctx, pccs.CA_ROOT)
	if err != nil {
		return nil, logex.Trace(err)
	}
	signingCert, err := ps.GetCertByID(ctx, pccs.CA_SIGNING)
	if err != nil {
		return nil, logex.Trace(err)
	}
	pckCert, err := ps.GetCertByID(ctx, pckType)
	if err != nil {
		return nil, logex.Trace(err)
	}

	var tcbInfo *pccs.TcbInfo
	var enclaveInfo *pccs.EnclaveIdentityInfo
	if v2 {
		if evaluation == nil {
			standard, readErr := ps.GetStandardTcbEvalNum(ctx, parser.Spec().TcbType())
			if readErr != nil {
				return nil, readErr
			}
			evaluation = &standard
		}
		tcbInfo, err = ps.GetTcbInfoWithEvalNum(ctx, parser.Spec().TcbType(), fmpsc, 3, evaluation)
	} else {
		tcbInfo, err = parser.TcbInfo(ctx, ps, fmpsc)
	}
	if err != nil {
		return nil, logex.Trace(err)
	}
	if v2 {
		enclaveInfo, err = ps.GetEnclaveIDWithEvalNum(ctx, parser.Spec().EnclaveIDType(), 4, evaluation)
	} else {
		enclaveInfo, err = parser.EnclaveID(ctx, ps)
	}
	if err != nil {
		return nil, logex.Trace(err)
	}

	var processorCrl []byte
	var platformCrl []byte

	if pckType == pccs.CA_PROCESSOR {
		processorCrl = pckCert.Crl
	} else if pckType == pccs.CA_PLATFORM {
		platformCrl = pckCert.Crl
	}

	return &Collateral{
		TcbInfo:         tcbInfo,
		QeIdentity:      enclaveInfo,
		RootCa:          rootCert.Cert,
		TcbSigningCa:    signingCert.Cert,
		PckCertChain:    nil,
		RootCaCrl:       rootCert.Crl,
		PckProcessorCrl: processorCrl,
		PckPlatformCrl:  platformCrl,
	}, nil
}

// Modified from https://github.com/automata-network/dcap-rs/blob/b218a9dcdf2aec8ee05f4d2bd055116947ddfced/src/types/collaterals.rs#L35-L105
func (c *Collateral) Encode() ([]byte, error) {
	if c == nil {
		return nil, logex.NewError("missing collateral")
	}
	tcbInfo, err := c.TcbInfo.Encode()
	if err != nil {
		return nil, logex.Trace(err, "encode TCB info")
	}
	qeId, err := c.QeIdentity.Encode()
	if err != nil {
		return nil, logex.Trace(err, "encode enclave identity")
	}

	fields := [][]byte{
		tcbInfo,
		qeId,
		c.RootCa,
		c.TcbSigningCa,
		c.PckCertChain,
		c.RootCaCrl,
		c.PckProcessorCrl,
		c.PckPlatformCrl,
	}

	totalLength := 4 * 8
	for _, field := range fields {
		if uint64(len(field)) > math.MaxUint32 || len(field) > int(^uint(0)>>1)-totalLength {
			return nil, logex.NewError("collateral field exceeds encoding size")
		}
		totalLength += len(field)
	}
	data := make([]byte, 0, totalLength)

	var lebuf [4]byte
	putU32Le := func(val uint32) {
		binary.LittleEndian.PutUint32(lebuf[:], val)
		data = append(data, lebuf[:]...)
	}

	for _, field := range fields {
		putU32Le(uint32(len(field)))
	}

	for _, field := range fields {
		data = append(data, field...)
	}
	return data, nil
}

// Both legacy proving backends use this exact little-endian input envelope.
// Validate/encode before uploading anything to a remote prover.
func encodeGuestInput(quote []byte, collateral *Collateral, timestamp uint64) ([]byte, error) {
	encoded, err := collateral.Encode()
	if err != nil {
		return nil, err
	}
	if uint64(len(quote)) > math.MaxUint32 || uint64(len(encoded)) > math.MaxUint32 ||
		uint64(len(quote))+uint64(len(encoded))+16 > uint64(^uint(0)>>1) {
		return nil, logex.NewError("guest input exceeds encoding size")
	}
	data := make([]byte, 0, 16+len(quote)+len(encoded))
	data = binary.LittleEndian.AppendUint64(data, timestamp)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(quote)))
	data = binary.LittleEndian.AppendUint32(data, uint32(len(encoded)))
	data = append(data, quote...)
	return append(data, encoded...), nil
}
