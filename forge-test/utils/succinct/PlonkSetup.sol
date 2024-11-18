// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SP1Verifier} from "@sp1-contracts/v3.0.0/SP1VerifierPlonk.sol";

contract PlonkSetup {
    function setup() public returns (address verifier) {
        SP1Verifier plonkVerifier = new SP1Verifier();
        verifier = address(plonkVerifier);
    }
}
