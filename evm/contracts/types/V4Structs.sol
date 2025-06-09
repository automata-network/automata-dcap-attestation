//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CommonStruct.sol";

/**
 * @notice V4 Intel TDX Quote uses this struct as the quote body
 * @dev Section A.3.2 of Intel V4 TDX DCAP API Library Documentation
 * @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L82-L103
 */
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
    bytes rtMr1; // 48 bytes
    bytes rtMr2; // 48 bytes
    bytes rtMr3; // 48 bytes
    bytes reportData; // 64 bytes
}

/**
 * @notice QE Report Certification Data struct definition
 * @dev this struct is the data that is stored as bytes array in CertificationData of type 6
 * @dev Section A.3.11 of Intel V4 TDX DCAP API Library Documentation
 * @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L143-L151
 */
struct QEReportCertificationData {
    EnclaveReport qeReport;
    bytes qeReportSignature;
    QEAuthData qeAuthData;
    CertificationData certification;
}

/**
 * @notice ECDSA V4 Quote Signature Data Structure Definition
 * @dev Section A.3.8 of Intel V4 TDX DCAP API Library Documentation
 */
struct ECDSAQuoteV4AuthData {
    bytes ecdsa256BitSignature; // 64 bytes
    bytes ecdsaAttestationKey; // 64 bytes
    QEReportCertificationData qeReportCertData;
}

/// In the Solidity implementation, quotes using different TEE types are represented by different structs.
/// As opposed to a unified struct, as seen in https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/Quote.h

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
