//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CommonStruct.sol";

/// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L153-L164
struct ECDSAQuoteV3AuthData {
    bytes ecdsa256BitSignature; // 64 bytes
    bytes ecdsaAttestationKey; // 64 bytes
    EnclaveReport qeReport; // 384 bytes
    bytes qeReportSignature; // 64 bytes
    QEAuthData qeAuthData;
    CertificationData certification;
}

struct V3Quote {
    Header header;
    EnclaveReport localEnclaveReport;
    ECDSAQuoteV3AuthData authData;
}
