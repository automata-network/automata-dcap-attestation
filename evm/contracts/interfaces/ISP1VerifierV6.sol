// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Keeps the upstream 0.8.20 compilation unit separate from DCAP 0.8.27.
interface ISP1VerifierV6 {
    function VERSION() external view returns (string memory);
    function VERIFIER_HASH() external view returns (bytes32);
    function VK_ROOT() external view returns (bytes32);
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}
