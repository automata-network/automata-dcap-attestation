//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteConstants.h
uint16 constant HEADER_LENGTH = 48;
bytes2 constant SUPPORTED_ATTESTATION_KEY_TYPE = 0x0200; // ECDSA_256_WITH_P256_CURVE (LE)
bytes4 constant SGX_TEE = 0x00000000;
bytes4 constant TDX_TEE = 0x00000081;
bytes16 constant VALID_QE_VENDOR_ID = 0x939a7233f79c4ca9940a0db3957f0607;
uint16 constant ENCLAVE_REPORT_LENGTH = 384;
uint16 constant TD_REPORT10_LENGTH = 584;
uint16 constant TD_REPORT15_LENGTH = 648;

// Header (48 bytes) + Body (minimum 384 bytes) + AuthDataSize (4 bytes) + AuthData:
// ECDSA_SIGNATURE (64 bytes) + ECDSA_KEY (64 bytes) + QE_REPORT_BYTES (384 bytes)
// + QE_REPORT_SIGNATURE (64 bytes) + QE_AUTH_DATA_SIZE (2 bytes) + QE_CERT_DATA_TYPE (2 bytes)
// + QE_CERT_DATA_SIZE (4 bytes)
uint16 constant MINIMUM_QUOTE_LENGTH = 1020;

// QUOTE_VERSION (2 bytes) + TEE_TYPE (4 bytes) + TCB_STATUS (1 byte) + FMSPC (6 bytes)
uint16 constant MINIMUM_OUTPUT_LENGTH = 13;
