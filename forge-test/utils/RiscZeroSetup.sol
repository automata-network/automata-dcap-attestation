// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";

abstract contract RiscZeroSetup {
    bytes32 public constant CONTROL_ROOT = hex"8b6dcf11d463ac455361b41fb3ed053febb817491bdea00fdb340e45013b852e";
    // NOTE: This has opposite byte order to the value in the risc0 repository.
    bytes32 public constant BN254_CONTROL_ID = hex"05a022e1db38457fb510bc347b30eb8f8cf3eda95587653d0eac19e1f10d164e";

    RiscZeroGroth16Verifier riscZeroVerifier;

    function setUpRiscZero() internal {
        riscZeroVerifier = new RiscZeroGroth16Verifier(CONTROL_ROOT, BN254_CONTROL_ID);
    }
}
