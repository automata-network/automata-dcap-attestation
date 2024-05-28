//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library V4Struct {
    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L42-L53
    struct Header {
        bytes2 version;
        bytes2 attestationKeyType;
        bytes4 teeType;
        bytes4 reserved;
        bytes16 qeVendorId;
        bytes20 userData;
    }

    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L82-L103
    struct ReportBody {
        bytes16 teeTcbSvn;
        bytes mrSeam; // 48 bytes
        bytes mrsignerSeam; // 48 bytes
        bytes8 seamAttributes;
        bytes8 tdAttributes;
        bytes8 xFAM;
        bytes mrTd; // 48 bytes
        bytes mrConfigId; // 48 bytes
        bytes mrOwner; // 48 bytes
        bytes mrOwnerConfig; // 48 bytes
        bytes rtMr0; // 48 bytes
        bytes rtMr1; // 48 nytes
        bytes rtMr2; // 48 bytes
        bytes rtMr3; // 48 bytes
        bytes reportData; // 64 bytes
    }

    struct CertificationData {
        uint16 certType;
        uint32 certDataSize;
        bytes[] decodedCertDataArray;
    }

    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L63-L80
    struct EnclaveReport {
        bytes16 cpuSvn;
        bytes4 miscSelect;
        bytes28 reserved1;
        bytes16 attributes;
        bytes32 mrEnclave;
        bytes32 reserved2;
        bytes32 mrSigner;
        bytes reserved3; // 96 bytes
        uint16 isvProdId;
        uint16 isvSvn;
        bytes reserved4; // 60 bytes
        bytes reportData; // 64 bytes - For QEReports, this contains the hash of the concatenation of attestation key and QEAuthData
    }

    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L128-L133
    struct QEAuthData {
        uint16 parsedDataSize;
        bytes data;
    }

    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L143-L151
    struct QEReportCertificationData {
        EnclaveReport qeReport;
        bytes qeReportSignature;
        QEAuthData qeAuthData;
        CertificationData certData;
    }

    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L166-L173
    /// this struct is modified from the original definition
    /// since we are expecting certificationData to be of certType == 6
    /// as per https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/45554a754ba8c03342cc394831fa7f04db08805c/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L85-L96
    struct ECDSAQuoteV4AuthData {
        bytes ecdsa256BitSignature; // 64 bytes
        bytes ecdsaAttestationKey; // 64 bytes
        QEReportCertificationData qeReportCertData;
    }

    struct ParsedV4Quote {
        Header header;
        ReportBody reportBody;
        ECDSAQuoteV4AuthData authData;
    }
}
