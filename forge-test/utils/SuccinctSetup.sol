// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// import {SP1Verifier} from "@sp1-contracts/v3.0.0/SP1VerifierGroth16.sol";
import {SP1Verifier} from "@sp1-contracts/v3.0.0/SP1VerifierPlonk.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

enum ProveOpt {
    Groth16,
    Plonk
}

abstract contract SuccinctSetup {
    function setupSP1Verifier(ProveOpt opt) internal returns (ISP1Verifier verifier) {
        // if (opt == ProveOpt.Groth16) {
        //     SP1Verifier groth16Verifier = new SP1Verifier();
        //     verifier = ISP1Verifier(address(groth16Verifier));
        // }
        // } else
        if (opt == ProveOpt.Plonk) {
            SP1Verifier plonkVerifier = new SP1Verifier();
            verifier = ISP1Verifier(address(plonkVerifier));
        }
    }
}
