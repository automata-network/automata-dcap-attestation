// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {SP1Verifier} from "@sp1-contracts/v6.1.0/SP1VerifierGroth16.sol";

/// @notice Distinct deployment name for SP1 SDK 6.8.0's official v6.1.0 circuit.
/// @dev No verifier logic or trusted-setup parameters are changed.
contract SP1Groth16VerifierV6 is SP1Verifier {}
