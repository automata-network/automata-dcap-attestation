package parser

// EnclaveReportBody represents an SGX enclave report body (384 bytes)
// Body type 1 in V5 quotes
type EnclaveReportBody struct {
	CpuSvn         [16]byte // CPU Security Version Number
	MiscSelect     uint32   // MISCSELECT
	Reserved1      [12]byte
	IsvExtProdId   [16]byte // ISV Extended Product ID
	Attributes     [16]byte // SGX Attributes (XFRM + flags)
	MrEnclave      [32]byte // Measurement of enclave
	Reserved2      [32]byte
	MrSigner       [32]byte // Measurement of signer
	Reserved3      [32]byte
	ConfigId       [64]byte // Config ID
	IsvProdId      uint16   // ISV Product ID
	IsvSvn         uint16   // ISV Security Version Number
	ConfigSvn      uint16   // Config SVN
	Reserved4      [42]byte
	IsvFamilyId    [16]byte // ISV Family ID
	UserReportData [64]byte // User-defined report data
}

// Td10ReportBody represents a TDX 1.0 report body (584 bytes)
// Body type 2 in V5 quotes
type Td10ReportBody struct {
	TeeTcbSvn     [16]byte // TEE TCB Security Version Number
	MrSeam        [48]byte // Measurement of SEAM module
	MrSignerSeam  [48]byte // Measurement of SEAM signer
	SeamAttributes [8]byte // SEAM Attributes
	TdAttributes  [8]byte  // TD Attributes
	Xfam          [8]byte  // Extended Feature Activation Mask
	MrTd          [48]byte // Measurement of TD
	MrConfigId    [48]byte // Config ID
	MrOwner       [48]byte // Owner measurement
	MrOwnerConfig [48]byte // Owner config measurement
	RtMr0         [48]byte // Runtime measurement register 0
	RtMr1         [48]byte // Runtime measurement register 1
	RtMr2         [48]byte // Runtime measurement register 2
	RtMr3         [48]byte // Runtime measurement register 3
	UserReportData [64]byte // User-defined report data
}

// Td15ReportBody represents a TDX 1.5 report body (648 bytes)
// Body type 3 in V5 quotes - extends Td10ReportBody with additional fields
type Td15ReportBody struct {
	Td10ReportBody          // Embedded TD 1.0 report (584 bytes)
	TeeTcbSvn2   [16]byte   // Additional TEE TCB SVN (TDX 1.5)
	MrServiceTd  [48]byte   // Measurement of Service TD (TDX 1.5)
}

// BodyTypeFromTeeType infers body type from TEE type (for V4 quotes)
func BodyTypeFromTeeType(teeType uint32) uint16 {
	switch teeType {
	case SGX_TEE_TYPE:
		return BODY_TYPE_SGX
	case TDX_TEE_TYPE:
		return BODY_TYPE_TDX10
	default:
		return 0
	}
}

// BodySizeFromType returns the body size for a given body type
func BodySizeFromType(bodyType uint16) uint32 {
	switch bodyType {
	case BODY_TYPE_SGX:
		return ENCLAVE_REPORT_BODY_SIZE
	case BODY_TYPE_TDX10:
		return TD10_REPORT_BODY_SIZE
	case BODY_TYPE_TDX15:
		return TD15_REPORT_BODY_SIZE
	default:
		return 0
	}
}
