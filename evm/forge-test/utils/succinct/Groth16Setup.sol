// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SP1Verifier} from "@sp1-contracts/v3.0.0/SP1VerifierGroth16.sol";

contract Groth16Setup {
    function setup() public returns (address verifier) {
        SP1Verifier groth16Verifier = new SP1Verifier();
        verifier = address(groth16Verifier);
    }
}
