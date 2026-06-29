// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Verifier} from "./Groth16Verifier.sol";
import {IPicoVerifier} from "./interfaces/IPicoVerifier.sol";

/// @title Pico Verifier
/// @author Brevis Network
/// @notice This contracts implements a solidity verifier for Pico.
contract PicoVerifier is Verifier, IPicoVerifier {
    /// @notice Thrown when the proof is invalid.
    error InvalidProof();

    /// @notice Hashes the public values to a field elements inside Bn254 using SHA256.
    /// @param publicValues The public values.
    function sha256PublicValues(bytes calldata publicValues) public pure returns (bytes32) {
        return sha256(publicValues) & bytes32(uint256((1 << 253) - 1));
    }

    /// @notice Verifies a proof with given public values and riscv verification key.
    /// @param riscvVkey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proof The proof of the riscv program execution in the Pico.
    function verifyPicoProof(bytes32 riscvVkey, bytes calldata publicValues, uint256[8] calldata proof) external view {
        bytes32 publicValuesDigest = sha256PublicValues(publicValues);
        verifyPicoProof(riscvVkey, publicValuesDigest, proof);
    }

    /// @notice Verifies a proof with given public values and riscv verification key.
    /// @param riscvVkey The verification key for the RISC-V program.
    /// @param publicValuesDigest The sha256 hash of bytes-encoded public values.
    /// @param proof The proof of the riscv program execution in the Pico.
    function verifyPicoProof(bytes32 riscvVkey, bytes32 publicValuesDigest, uint256[8] calldata proof) public view {
        uint256[2] memory inputs;
        inputs[0] = uint256(riscvVkey);
        inputs[1] = uint256(publicValuesDigest);
        this.verifyProof(proof, inputs);
    }
}