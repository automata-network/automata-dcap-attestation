package parser

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/pccs"
	"github.com/chzyer/logex"
)

var led = binary.LittleEndian

var ErrInvalidPemType = logex.Define("Invalid PEM type: %v")
var ErrUnsupportedQuoteVersion = logex.Define("unsupported quote version: %v")
var ErrUnknownTeeType = logex.Define("unknown TEE type: %v")
var ErrUnknownBodyType = logex.Define("unknown body type: %v")
var ErrQuoteTooShort = logex.Define("quote too short: need %v bytes, got %v")
var OidFmpsc = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}

const SGX_TEE_TYPE = uint32(0x00000000)
const TDX_TEE_TYPE = uint32(0x00000081)

// Quote versions
const V3_QUOTE = uint16(0x03)
const V4_QUOTE = uint16(0x04)
const V5_QUOTE = uint16(0x05)

// Body types (V5 explicit, V4 inferred from TEE type)
const (
	BODY_TYPE_SGX   = uint16(1) // EnclaveReportBody - 384 bytes
	BODY_TYPE_TDX10 = uint16(2) // Td10ReportBody - 584 bytes
	BODY_TYPE_TDX15 = uint16(3) // Td15ReportBody - 648 bytes (V5 only)
)

// Body sizes in bytes
const (
	ENCLAVE_REPORT_BODY_SIZE = 384
	TD10_REPORT_BODY_SIZE    = 584
	TD15_REPORT_BODY_SIZE    = 648
)

// Header size is constant across all versions
const QUOTE_HEADER_SIZE = 48

type QuoteParser struct {
	spec  QuoteSpec
	quote []byte
}

func NewQuoteParser(quote []byte) (*QuoteParser, error) {
	return NewQuoteParserSafe(quote)
}

// NewQuoteParserSafe is like NewQuoteParser but returns an error instead of panicking
// on unsupported quote versions or invalid data
func NewQuoteParserSafe(quote []byte) (*QuoteParser, error) {
	spec, err := DetectQuoteSpecSafe(quote)
	if err != nil {
		return nil, logex.Trace(err)
	}
	parser := &QuoteParser{spec: spec, quote: quote}
	if _, _, err := parser.certDataBounds(); err != nil {
		return nil, err
	}
	return parser, nil
}

func (q *QuoteParser) CertData() ([]byte, error) {
	start, end, err := q.certDataBounds()
	if err != nil {
		return nil, err
	}
	return q.quote[start:end], nil
}

func (q *QuoteParser) Quote() []byte {
	return q.quote
}

func (q *QuoteParser) Spec() QuoteSpec {
	return q.spec
}

func (q *QuoteParser) CertDataOffset() (int, error) {
	start, _, err := q.certDataBounds()
	return start, err
}

// Revalidate at the point of use: the caller may still own/mutate the quote slice.
// Ignore bytes outside the declared payload, as existing legacy fixtures require.
func (q *QuoteParser) certDataBounds() (int, int, error) {
	if q == nil {
		return 0, 0, logex.NewError("missing quote parser")
	}
	spec, err := DetectQuoteSpecSafe(q.quote)
	if err != nil {
		return 0, 0, err
	}
	version := led.Uint16(q.quote[:2])
	qeAuthOffset := spec.AuthDataSizeOffset()
	prefix := 576
	if version != V3_QUOTE {
		prefix = 582
	}
	authStart := qeAuthOffset - prefix
	if len(q.quote) < authStart {
		return 0, 0, ErrQuoteTooShort.Format(authStart, len(q.quote))
	}
	authLength := led.Uint32(q.quote[authStart-4 : authStart])
	if uint64(authLength) > uint64(len(q.quote)-authStart) || authLength < uint32(prefix+8) {
		return 0, 0, logex.NewError("invalid quote authentication length")
	}
	end := authStart + int(authLength)
	if version != V3_QUOTE {
		if led.Uint16(q.quote[authStart+128:authStart+130]) != 6 {
			return 0, 0, logex.NewError("expected QE report certification type 6")
		}
		qeLength := led.Uint32(q.quote[authStart+130 : authStart+134])
		if uint64(qeLength) > uint64(end-authStart-134) || qeLength < uint32(prefix+8-134) {
			return 0, 0, logex.NewError("invalid QE report certification length")
		}
		end = authStart + 134 + int(qeLength)
	}
	qeAuthLength := int(led.Uint16(q.quote[qeAuthOffset : qeAuthOffset+2]))
	certHeader := qeAuthOffset + 2
	if qeAuthLength > end-certHeader-6 {
		return 0, 0, logex.NewError("invalid QE authentication length")
	}
	certHeader += qeAuthLength
	if led.Uint16(q.quote[certHeader:certHeader+2]) != 5 {
		return 0, 0, logex.NewError("expected PCK certificate chain type 5")
	}
	certLength := led.Uint32(q.quote[certHeader+2 : certHeader+6])
	start := certHeader + 6
	if uint64(certLength) > uint64(end-start) {
		return 0, 0, logex.NewError("invalid PCK certificate length")
	}
	return start, start + int(certLength), nil
}

func (q *QuoteParser) PckIssuer(cert *x509.Certificate) string {
	return cert.Issuer.CommonName
}

func (q *QuoteParser) SgxExt(pck *x509.Certificate) ([]SgxExt, error) {
	for _, ext := range pck.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}) {
			var exts []SgxExt
			if _, err := asn1.Unmarshal(ext.Value, &exts); err != nil {
				return nil, logex.Trace(err)
			}
			return exts, nil
		}
	}
	return nil, nil
}

func (q *QuoteParser) TcbInfo(ctx context.Context, ps *pccs.Client, fmspc string) (*pccs.TcbInfo, error) {
	tcbType := q.spec.TcbType()
	tcbVersion := q.spec.TcbVersion()

	tcbInfo, err := ps.GetTcbInfo(ctx, tcbType, fmspc, tcbVersion)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return tcbInfo, nil
}

func (q *QuoteParser) EnclaveID(ctx context.Context, ps *pccs.Client) (*pccs.EnclaveIdentityInfo, error) {
	info, err := ps.GetEnclaveID(ctx, q.spec.EnclaveIDType(), q.spec.Version())
	if err != nil {
		return nil, logex.Trace(err)
	}
	return info, nil
}

func (q *QuoteParser) Fmpsc(exts []SgxExt) string {
	for _, ext := range exts {
		if ext.OID.Equal(OidFmpsc) {
			return hex.EncodeToString(ext.Value.Bytes)
		}
	}
	return ""
}

func (q *QuoteParser) PckType(pck *x509.Certificate) (uint8, error) {
	var pckType uint8
	switch name := q.PckIssuer(pck); name {
	case "Intel SGX PCK Platform CA":
		pckType = pccs.CA_PLATFORM
	case "Intel SGX PCK Processor CA":
		pckType = pccs.CA_PROCESSOR
	default:
		return 0, logex.NewErrorf("unknown pck issuer: %v", name)
	}
	return pckType, nil
}

func (q *QuoteParser) Certificates() ([]*x509.Certificate, error) {
	certData, err := q.CertData()
	if err != nil {
		return nil, err
	}
	// Intel certificate-chain payloads can have one terminal NUL.
	certData = bytes.TrimSpace(certData)
	certData = bytes.TrimSuffix(certData, []byte{0})
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(certData)) != 0 {
		certData = bytes.TrimSpace(certData)
		if !bytes.HasPrefix(certData, []byte("-----BEGIN ")) {
			return nil, logex.NewError("invalid PCK certificate PEM data")
		}
		pemBlock, rest := pem.Decode(certData)
		if pemBlock == nil {
			return nil, logex.NewError("invalid PCK certificate PEM block")
		}
		if pemBlock.Type != "CERTIFICATE" {
			return nil, ErrInvalidPemType.Format(pemBlock.Type)
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, logex.Trace(err)
		}
		certs = append(certs, cert)
		certData = rest
	}
	if len(certs) == 0 {
		return nil, logex.NewError("quote contains no PCK certificates")
	}
	return certs, nil
}

type V3QuoteSpec struct{}

func (q *V3QuoteSpec) AuthDataSizeOffset() int {
	// 48 + 384 + 4 + 64 + 64 + 384 + 64
	return 1012
}

func (q *V3QuoteSpec) TcbType() uint8 {
	return 0
}

func (q *V4QuoteSpec) TcbType() uint8 {
	switch q.TeeType {
	case TDX_TEE_TYPE:
		return 1
	case SGX_TEE_TYPE:
		return 0
	default:
		panic("unknown teeType")
	}
}

func (q *V3QuoteSpec) TcbVersion() uint32 {
	return 2
}

func (q *V4QuoteSpec) TcbVersion() uint32 {
	return 3
}

func (q *V3QuoteSpec) Version() uint32 {
	return 3
}

func (q *V4QuoteSpec) Version() uint32 {
	return 4
}

func (q *V3QuoteSpec) EnclaveIDType() uint8 {
	return pccs.ENCLAVE_ID_QE
}

func (q *V4QuoteSpec) EnclaveIDType() uint8 {
	switch q.TeeType {
	case TDX_TEE_TYPE:
		return pccs.ENCLAVE_ID_TDQE
	case SGX_TEE_TYPE:
		return pccs.ENCLAVE_ID_QE
	default:
		panic("unknown teeType")
	}
}

type V4QuoteSpec struct {
	TeeType uint32
}

func (q *V4QuoteSpec) AuthDataSizeOffset() int {
	switch q.TeeType {
	case SGX_TEE_TYPE:
		// 48 + 384 + 4 + 64 + 64 + 2 + 4 + 384 + 64
		return 1018
	case TDX_TEE_TYPE:
		// 48 + 584 + 4 + 64 + 64 + 2 + 4 + 384 + 64
		return 1218
	default:
		panic("invalid TEE Type")
	}
}

// V5QuoteSpec handles Quote V5 format which has explicit body_type and body_size fields
type V5QuoteSpec struct {
	BodyType uint16
	BodySize uint32
}

func (q *V5QuoteSpec) AuthDataSizeOffset() int {
	// V5 layout: 48 (header) + 2 (body_type) + 4 (body_size) + body_size + 4 (sig_len) + 64 + 64 + 2 + 4 + 384 + 64
	// = 54 + body_size + 586
	return 54 + int(q.BodySize) + 4 + 64 + 64 + 2 + 4 + 384 + 64
}

func (q *V5QuoteSpec) TcbType() uint8 {
	switch q.BodyType {
	case BODY_TYPE_SGX:
		return 0
	case BODY_TYPE_TDX10, BODY_TYPE_TDX15:
		return 1
	default:
		panic("unknown body type")
	}
}

func (q *V5QuoteSpec) TcbVersion() uint32 {
	return 3
}

func (q *V5QuoteSpec) Version() uint32 {
	return 5
}

func (q *V5QuoteSpec) EnclaveIDType() uint8 {
	switch q.BodyType {
	case BODY_TYPE_SGX:
		return pccs.ENCLAVE_ID_QE
	case BODY_TYPE_TDX10, BODY_TYPE_TDX15:
		return pccs.ENCLAVE_ID_TDQE
	default:
		panic("unknown body type")
	}
}

type QuoteSpec interface {
	AuthDataSizeOffset() int
	TcbType() uint8
	TcbVersion() uint32
	EnclaveIDType() uint8
	Version() uint32
}

func DetectQuoteSpec(quote []byte) (QuoteSpec, error) {
	return DetectQuoteSpecSafe(quote)
}

// DetectQuoteSpecSafe detects the quote version and returns the appropriate QuoteSpec
// Returns an error for unsupported versions or malformed quotes
func DetectQuoteSpecSafe(quote []byte) (QuoteSpec, error) {
	if len(quote) < QUOTE_HEADER_SIZE {
		return nil, ErrQuoteTooShort.Format(QUOTE_HEADER_SIZE, len(quote))
	}

	ed := binary.LittleEndian
	version := ed.Uint16(quote[0:2])
	teeType := ed.Uint32(quote[4:8])

	switch version {
	case V3_QUOTE:
		if teeType != SGX_TEE_TYPE {
			return nil, ErrUnknownTeeType.Format(teeType)
		}
		return &V3QuoteSpec{}, nil
	case V4_QUOTE:
		// Validate TEE type for V4
		if teeType != SGX_TEE_TYPE && teeType != TDX_TEE_TYPE {
			return nil, ErrUnknownTeeType.Format(teeType)
		}
		return &V4QuoteSpec{
			TeeType: teeType,
		}, nil
	case V5_QUOTE:
		// V5 needs additional bytes for body_type and body_size
		if len(quote) < QUOTE_HEADER_SIZE+6 {
			return nil, ErrQuoteTooShort.Format(QUOTE_HEADER_SIZE+6, len(quote))
		}
		// V5 has explicit body_type (2 bytes) and body_size (4 bytes) after the 48-byte header
		bodyType := ed.Uint16(quote[QUOTE_HEADER_SIZE : QUOTE_HEADER_SIZE+2])
		bodySize := ed.Uint32(quote[QUOTE_HEADER_SIZE+2 : QUOTE_HEADER_SIZE+6])

		// Validate body type
		if bodyType != BODY_TYPE_SGX && bodyType != BODY_TYPE_TDX10 && bodyType != BODY_TYPE_TDX15 {
			return nil, ErrUnknownBodyType.Format(bodyType)
		}
		expectedSize := uint32(ENCLAVE_REPORT_BODY_SIZE)
		expectedTee := SGX_TEE_TYPE
		if bodyType != BODY_TYPE_SGX {
			expectedTee = TDX_TEE_TYPE
			expectedSize = TD10_REPORT_BODY_SIZE
			if bodyType == BODY_TYPE_TDX15 {
				expectedSize = TD15_REPORT_BODY_SIZE
			}
		}
		if teeType != expectedTee {
			return nil, ErrUnknownTeeType.Format(teeType)
		}
		if bodySize != expectedSize {
			return nil, logex.NewErrorf("invalid quote body size: expected %v, got %v", expectedSize, bodySize)
		}

		return &V5QuoteSpec{
			BodyType: bodyType,
			BodySize: bodySize,
		}, nil
	default:
		return nil, ErrUnsupportedQuoteVersion.Format(version)
	}
}

type SgxExt struct {
	OID   asn1.ObjectIdentifier
	Value asn1.RawValue
}
