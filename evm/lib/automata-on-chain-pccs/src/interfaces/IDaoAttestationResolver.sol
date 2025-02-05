// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/**
 * @title PCCS Data Access Object (DAO) Resolver
 * @notice The resolver associates a collateral key with an attestation ID,
 * which points to the collateral data that can either be stored interanlly in the
 * Resolver contract or to an attestation registry, such as EAS.
 * @notice The Resolver is intended to be deployed only ONCE and must be permanently immutable
 * @notice Future upgrades/re-deployments of all other PCCS contracts can simply point to this Resolver
 * to retain collateral data.
 */

interface IDaoAttestationResolver {
    /**
     * @param key - identifies a specific collateral. Definition varies by DAO
     * @return collateralAttId - the attestation ID of the collateral
     */
    function collateralPointer(bytes32 key) external view returns (bytes32 collateralAttId);

    /**
     * @notice the hash of the collateral is RECOMMENDED to be stored as a separate attestation
     * @dev optimizes SLOAD read cost for checking collateral correctness. (Reading the entire collateral vs 32-byte hash)
     * @param key - identifies a specific collateral. Definition varies by DAO
     */
    function collateralHashPointer(bytes32 key) external view returns (bytes32 collateralHashAttId);

    /**
     * @notice writes collateral data on-chain
     * @param key - identifies a specific collateral. Definition varies by DAO
     * @param attData - serialized collateral data
     * @param attDataHash - hash of attData
     * @return attestationId - the ID to retrieve attData
     * @return hashAttestationid - the ID to retrieve the hash of attData
     */
    function attest(bytes32 key, bytes calldata attData, bytes32 attDataHash)
        external
        returns (bytes32 attestationId, bytes32 hashAttestationid);

    /**
     * @param attestationId - identifier that is assigned to the data upon attestation
     */
    function readAttestation(bytes32 attestationId) external view returns (bytes memory attData);
}
