//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {TCBStatus} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";
import {X509CertObj} from "@automata-network/on-chain-pccs/helpers/X509Helper.sol";

/// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L42-L53
struct Header {
    uint16 version;
    bytes2 attestationKeyType;
    bytes4 teeType;
    bytes2 qeSvn;
    bytes2 pceSvn;
    bytes16 qeVendorId;
    bytes20 userData;
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

/// @dev Modified from https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/QuoteVerification/QuoteStructures.h#L135-L141
struct CertificationData {
    uint16 certType;
    uint32 certDataSize;
    PCKCollateral pck;
}

/// ========== CUSTOM TYPES ==========

struct PCKCollateral {
    X509CertObj[] pckChain; // base64 decoded array containing the PCK chain
    PCKCertTCB pckExtension;
}

struct PCKCertTCB {
    uint16 pcesvn;
    uint8[] cpusvns;
    bytes fmspcBytes;
    bytes pceidBytes;
}

struct Output {
    uint16 quoteVersion; // BE
    bytes4 tee; // BE
    TCBStatus tcbStatus;
    bytes6 fmspcBytes;
    bytes quoteBody;
    string[] advisoryIDs;
}
