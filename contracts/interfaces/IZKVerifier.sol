//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface IZKVerifier {
    // 51abd95c
    error Unknown_Zk_Coprocessor();

    /**
     * @param zkCoprocessorType 0 - RiscZero, 1 - Succinct... etc.
     * @return this is either the IMAGE_ID for RiscZero Guest Program or
     * Succiinct Program Verifying Key
     */
    function programIdentifier(uint8 zkCoprocessorType) external view returns (bytes32);

    /**
     * @notice get the contract verifier for the provided ZK Co-processor
     */
    function zkVerifier(uint8 zkCoprocessorType) external view returns (address);

    /**
     * @param output - The output of the Guest program, this includes:
     * - VerifiedOutput struct
     * - RootCA hash
     * - TCB Signing CA hash
     * - Root CRL hash
     * - Platform or Processor CRL hash
     * @param proofBytes - abi-encoded tuple of:
     * - The ZK Co-Processor Type
     * - The encoded cryptographic proof (i.e. SNARK)).
     */
    function verifyAndAttestWithZKProof(bytes calldata output, bytes calldata proofBytes)
        external
        returns (bool success, bytes memory verifiedOutput);
}
