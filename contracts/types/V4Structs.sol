//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CommonStruct.sol";

/// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L82-L103
struct TD10ReportBody {
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

/// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L143-L151
struct QEReportCertificationData {
    EnclaveReport qeReport;
    bytes qeReportSignature;
    QEAuthData qeAuthData;
    CertificationData certification;
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

struct V4SGXQuote {
    Header header;
    EnclaveReport localEnclaveReport;
    ECDSAQuoteV4AuthData authData;
}

struct V4TDXQuote {
    Header header;
    TD10ReportBody reportBody;
    ECDSAQuoteV4AuthData authData;
}
