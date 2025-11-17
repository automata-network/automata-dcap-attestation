//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

enum ZkCoProcessorType {
    // if the ZkCoProcessorType is included as None in the AttestationSubmitted event log
    // it indicates that the attestation of the DCAP quote is executed entirely on-chain
    None,
    RiscZero,
    Succinct,
    Pico
}

/**
 * @title ZK Co-Processor Configuration Object
 * @param dcapProgramIdentifier - This is the identifier of the ZK Program, required for
 * verification
 * @param zkVerifier - Points to the address of the ZK Verifier contract. Ideally
 * this should be pointing to a universal verifier, that may support multiple proof types and/or versions.
 */
struct ZkCoProcessorConfig {
    bytes32 dcapProgramIdentifier;
    address zkVerifier;
}

interface IAutomataDcapAttestation {
    /**
     * @param zkCoProcessorType 1 - RiscZero, 2 - Succinct... etc.
     * @return this returns the latest DCAP program identifier for the specified ZK Co-processor
     */
    function programIdentifier(ZkCoProcessorType zkCoProcessorType) external view returns (bytes32);

    /**
     * @param zkCoProcessorType 1 - RiscZero, 2 - Succinct... etc.
     * @return this returns the list of all DCAP program identifiers for the specified ZK Co-processor
     */
    function programIdentifiers(ZkCoProcessorType zkCoProcessorType) external view returns (bytes32[] memory);

    /**
     * @notice gets the default (universal) ZK verifier for the provided ZK Co-processor
     */
    function zkVerifier(ZkCoProcessorType zkCoProcessorType) external view returns (address);

    /**
     * @notice gets the specific ZK Verifier for the provided ZK Co-processor and proof selector
     * @notice this function will revert if the provided selector has been frozen
     * @notice otherwise, if a specific ZK verifier is not configured for the provided selector
     * @notice it will return the default ZK verifier
     */
    function zkVerifier(ZkCoProcessorType zkCoProcessorType, bytes4 selector) external view returns (address);

    function verifyAndAttestOnChain(bytes calldata rawQuote)
        external
        payable
        returns (bool success, bytes memory output);

    function verifyAndAttestOnChain(bytes calldata rawQuote, uint32 tcbEvaluationDataNumber)
        external
        payable
        returns (bool success, bytes memory output);

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external payable returns (bool success, bytes memory verifiedOutput);

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes,
        bytes32 programIdentifier,
        uint32 tcbEvaluationDataNumber
    ) external payable returns (bool success, bytes memory verifiedOutput);
}