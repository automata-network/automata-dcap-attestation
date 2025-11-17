pragma solidity >0.8.0;

bytes32 constant PCCS_ROUTER_SALT = keccak256(bytes("PCCS_ROUTER_SALT"));
bytes32 constant DCAP_ATTESTATION_SALT = keccak256(bytes("DCAP_ATTESTATION_SALT"));

// Compute salt for any verifier version
// Usage: verifierSalt(3) returns same value as V3_VERIFIER_SALT
// Note: For new versions, use this function instead of adding new constants
function verifierSalt(uint16 version) pure returns (bytes32) {
    return keccak256(abi.encodePacked("QUOTE_VERIFIER_V", version));
}
