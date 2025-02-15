// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";

abstract contract RiscZeroSetup {
    RiscZeroGroth16Verifier riscZeroVerifier;

    function setUpRiscZero() internal {
        riscZeroVerifier = new RiscZeroGroth16Verifier(
            ControlID.CONTROL_ROOT, 
            ControlID.BN254_CONTROL_ID
        );
    }
}
