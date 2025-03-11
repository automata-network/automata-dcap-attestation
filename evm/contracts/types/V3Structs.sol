//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CommonStruct.sol";

/**
 * @title V3Structs
 * @notice Structs that are specific to Intel SGX DCAP Quote Version 3
 * @dev Intel V3 SGX DCAP API Library: https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
 */

/**
 * @notice ECDSA V3 Quote Signature Data Structure Definition
 * @dev Table 4 in Section A.4 of Intel V3 SGX DCAP API Library Documentation
 * @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L153-L164
 */
struct ECDSAQuoteV3AuthData {
    bytes ecdsa256BitSignature; // 64 bytes
    bytes ecdsaAttestationKey; // 64 bytes
    EnclaveReport qeReport; // 384 bytes
    bytes qeReportSignature; // 64 bytes
    QEAuthData qeAuthData;
    CertificationData certification;
}

/**
 * @dev Section A.4 of Intel V3 SGX DCAP API Library Documentation
 */
struct V3Quote {
    Header header;
    EnclaveReport localEnclaveReport;
    ECDSAQuoteV3AuthData authData;
}
