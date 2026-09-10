// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

struct OutputV2 {
    uint16 formatMajorVersion;
    uint16 formatMinorVersion;
    uint16 quoteVersion;
    uint16 quoteBodyType;
    uint8 tcbStatus;
    bytes6 fmspc;
    bytes16 ppid;
    bytes16 piid;
    bool piidPresent;
    uint64 timestamp;
    // TCB info, QE identity, root cert, signing cert, root CRL, PCK CRL.
    bytes32[6] collateralHashes;
    bytes32 fullQuoteHash;
    bytes quoteBody;
    string[] advisoryIDs;
}
