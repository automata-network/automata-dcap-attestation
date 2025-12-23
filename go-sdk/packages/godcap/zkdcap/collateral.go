package zkdcap

import (
	"context"
	"encoding/binary"

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
	certs, err := parser.Certificates()
	if err != nil {
		return nil, logex.Trace(err)
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

	tcbInfo, err := parser.TcbInfo(ctx, ps, fmpsc)
	if err != nil {
		return nil, logex.Trace(err)
	}
	enclaveInfo, err := parser.EnclaveID(ctx, ps)
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
func (c *Collateral) Encode() []byte {
	tcbInfo := c.TcbInfo.Encode()
	qeId := c.QeIdentity.Encode()

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
	return data
}
