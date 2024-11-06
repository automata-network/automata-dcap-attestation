//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/**
 * @title Interface standard that implement attestation contracts whose verification logic can be implemented
 * both on-chain and with ZK proofs
 * @notice The interface simply provides two verification methods for a given attestation input.
 * The user can either pay a possibly hefty gas cost to fully verify an attestation fully on-chain
 * OR
 * Provides ZK proofs from executing an off-chain program where the verification of such attestation is conducted.
 * @dev should also implement Risc0 Guest Program to use this interface.
 * See https://dev.risczero.com/api/blockchain-integration/bonsai-on-eth to learn more
 */
interface IAttestation {
    /**
     * @notice full on-chain verification for an attestation
     * @dev must further specify the structure of inputs/outputs, to be serialized and passed to this method
     * @param rawQuote - Intel DCAP Quote serialized in raw bytes
     * @return success - whether the quote has been successfully verified or not
     * @return output - the output upon completion of verification. The output data may require post-processing by the consumer.
     * For verification failures, the output is simply a UTF-8 encoded string, describing the reason for failure.
     * @dev can directly type cast the failed output as a string
     */
    function verifyAndAttestOnChain(bytes calldata rawQuote) external returns (bool success, bytes memory output);

    /**
     * @notice verifies an attestation using SNARK proofs
     * @param output - The output of the Guest program, this includes:
     * - VerifiedOutput struct
     * - RootCA hash
     * - TCB Signing CA hash
     * - Root CRL hash
     * - Platform or Processor CRL hash
     * @param proofBytes - abi-encoded tuple of:
     * - The ZK Co-Processor Type (uint8 value)
     * - The encoded cryptographic proof (i.e. SNARK)).
     */
    function verifyAndAttestWithZKProof(bytes calldata output, bytes calldata proofBytes)
        external
        returns (bool success, bytes memory verifiedOutput);
}
