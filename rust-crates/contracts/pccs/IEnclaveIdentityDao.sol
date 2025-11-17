// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @dev This is a simple representation of the Identity.json in string as a Solidity object.
 * @param identityStr Identity string object body. Needs to be parsed
 * and converted as IdentityObj.
 * @param signature The signature to be passed as bytes array
 */
struct EnclaveIdentityJsonObj {
    string identityStr;
    bytes signature;
}

enum EnclaveId {
    QE,
    QVE,
    TD_QE
}

/// @dev Full Solidity Object representation of Identity.json
struct IdentityObj {
    EnclaveId id;
    uint32 version;
    uint64 issueDateTimestamp; // UNIX Epoch Timestamp in seconds
    uint64 nextUpdateTimestamp; // UNIX Epoch Timestamp in seconds
    uint32 tcbEvaluationDataNumber;
    bytes4 miscselect;
    bytes4 miscselectMask;
    bytes16 attributes;
    bytes16 attributesMask;
    bytes32 mrsigner;
    uint16 isvprodid;
    Tcb[] tcb;
}

enum EnclaveIdTcbStatus {
    SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED,
    OK,
    SGX_ENCLAVE_REPORT_ISVSVN_REVOKED,
    SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE
}

struct Tcb {
    uint16 isvsvn;
    uint256 dateTimestamp;
    EnclaveIdTcbStatus status;
}

interface IEnclaveIdentityDao {
    function getEnclaveIdentity(uint256 id, uint256 version)
        external
        view
        returns (EnclaveIdentityJsonObj memory enclaveIdObj);

    function getEnclaveIdentityIssuerChain() external view returns (bytes memory signingCert, bytes memory rootCert);

    function upsertEnclaveIdentity(uint256 id, uint256 version, EnclaveIdentityJsonObj calldata enclaveIdentityObj)
        external
        returns (bytes32 attestationId);
}
