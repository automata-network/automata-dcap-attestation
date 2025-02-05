// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CA} from "../Common.sol";
import {
    EnclaveIdentityHelper, EnclaveIdentityJsonObj, EnclaveId, IdentityObj
} from "../helpers/EnclaveIdentityHelper.sol";

import {DaoBase} from "./DaoBase.sol";
import {SigVerifyBase} from "./SigVerifyBase.sol";
import {PcsDao} from "./PcsDao.sol";

/// @notice The on-chain schema for Identity.json is stored as ABI-encoded tuple of (EnclaveIdentityHelper.IdentityObj, string, bytes)
/// @notice see {{ EnclaveIdentityHelper.IdentityObj }} for struct definition

/**
 * @title Enclave Identity Data Access Object
 * @notice This contract is heavily inspired by Section 4.2.9 in the Intel SGX PCCS Design Guideline
 * https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf
 * @dev should extends this contract and use the provided read/write methods to interact with
 * Identity.json data published on-chain.
 */
abstract contract EnclaveIdentityDao is DaoBase, SigVerifyBase {
    PcsDao public Pcs;
    EnclaveIdentityHelper public EnclaveIdentityLib;

    // first 4 bytes of keccak256("ENCLAVE_ID_MAGIC")
    bytes4 constant ENCLAVE_ID_MAGIC = 0xff818fce;

    // 289fa0cb
    error Enclave_Id_Mismatch();
    // 4e0f5696
    error Incorrect_Enclave_Id_Version();
    // 8de7233f
    error Invalid_TCB_Cert_Signature();
    // 9ac04499
    error Enclave_Id_Expired();
    // 7a204327
    error Enclave_Id_Out_Of_Date();

    event UpsertedEnclaveIdentity(uint256 indexed id, uint256 indexed version);

    constructor(address _resolver, address _p256, address _pcs, address _enclaveIdentityHelper, address _x509Helper)
        DaoBase(_resolver)
        SigVerifyBase(_p256, _x509Helper)
    {
        Pcs = PcsDao(_pcs);
        EnclaveIdentityLib = EnclaveIdentityHelper(_enclaveIdentityHelper);
    }

    /**
     * @notice computes the key that is mapped to the collateral attestation ID
     * NOTE: the "version" indicated here is taken from the input parameter (e.g. v3 vs v4);
     * NOT the "version" value found in the Enclave Identity JSON
     * @return key = keccak256(ENCLAVE_ID_MAGIC ++ id ++ version)
     */
    function ENCLAVE_ID_KEY(uint256 id, uint256 version) public pure returns (bytes32 key) {
        key = keccak256(abi.encodePacked(ENCLAVE_ID_MAGIC, id, version));
    }

    /**
     * @notice Section 4.2.9 (getEnclaveIdentity)
     * @notice Gets the enclave identity.
     * @param id 0: QE; 1: QVE; 2: TD_QE
     * https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/39989a42bbbb0c968153a47254b6de79a27eb603/QuoteVerification/QVL/Src/AttestationLibrary/src/Verifiers/EnclaveIdentityV2.h#L49-L52
     * @param version the input version parameter (v3 or v4)
     * @return enclaveIdObj See {EnclaveIdentityHelper.sol} to learn more about the structure definition
     */
    function getEnclaveIdentity(uint256 id, uint256 version)
        external
        view
        returns (EnclaveIdentityJsonObj memory enclaveIdObj)
    {
        bytes memory attestedIdentityData = _onFetchDataFromResolver(ENCLAVE_ID_KEY(id, version), false);
        if (attestedIdentityData.length > 0) {
            (, enclaveIdObj.identityStr, enclaveIdObj.signature) =
                abi.decode(attestedIdentityData, (IdentityObj, string, bytes));
        }
    }

    /**
     * @notice Section 4.2.9 (upsertEnclaveIdentity)
     * @param id 0: QE; 1: QVE; 2: TD_QE
     * https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/39989a42bbbb0c968153a47254b6de79a27eb603/QuoteVerification/QVL/Src/AttestationLibrary/src/Verifiers/EnclaveIdentityV2.h#L49-L52
     * @param version the input version parameter (v3 or v4)
     * @param enclaveIdentityObj See {EnclaveIdentityHelper.sol} to learn more about the structure definition
     */
    function upsertEnclaveIdentity(uint256 id, uint256 version, EnclaveIdentityJsonObj calldata enclaveIdentityObj)
        external
        returns (bytes32 attestationId)
    {
        _validateQeIdentity(enclaveIdentityObj);
        (bytes32 key, bytes memory req) = _buildEnclaveIdentityAttestationRequest(id, version, enclaveIdentityObj);
        bytes32 hash = sha256(bytes(enclaveIdentityObj.identityStr));
        attestationId = _attestEnclaveIdentity(req, hash, key);

        emit UpsertedEnclaveIdentity(id, version);
    }

    /**
     * @notice Fetches the Enclave Identity issuer chain
     * @return signingCert - DER encoded Intel TCB Signing Certificate
     * @return rootCert - DER encoded Intel SGX Root CA
     */
    function getEnclaveIdentityIssuerChain() external view returns (bytes memory signingCert, bytes memory rootCert) {
        signingCert = _onFetchDataFromResolver(Pcs.PCS_KEY(CA.SIGNING, false), false);
        rootCert = _onFetchDataFromResolver(Pcs.PCS_KEY(CA.ROOT, false), false);
    }

    /**
     * @notice attests collateral via the Resolver
     * @return attestationId
     */
    function _attestEnclaveIdentity(bytes memory reqData, bytes32 hash, bytes32 key)
        internal
        virtual
        returns (bytes32 attestationId)
    {
        (attestationId,) = resolver.attest(key, reqData, hash);
    }

    /**
     * @notice constructs the Identity.json attestation data
     */
    function _buildEnclaveIdentityAttestationRequest(
        uint256 id,
        uint256 version,
        EnclaveIdentityJsonObj calldata enclaveIdentityObj
    ) private view returns (bytes32 key, bytes memory reqData) {
        IdentityObj memory identity = EnclaveIdentityLib.parseIdentityString(enclaveIdentityObj.identityStr);
        if (id != uint256(identity.id)) {
            revert Enclave_Id_Mismatch();
        }

        if (id == uint256(EnclaveId.TD_QE) && version != 4 && version != 5) {
            revert Incorrect_Enclave_Id_Version();
        } 

        if (block.timestamp < identity.issueDateTimestamp || block.timestamp > identity.nextUpdateTimestamp) {
            revert Enclave_Id_Expired();
        }

        // make sure new collateral is "newer"
        key = ENCLAVE_ID_KEY(id, version);
        bytes memory existingData = _onFetchDataFromResolver(key, false);
        if (existingData.length > 0) {
            (IdentityObj memory existingIdentity, , ) =
                abi.decode(existingData, (IdentityObj, string, bytes));
            bool outOfDate = existingIdentity.tcbEvaluationDataNumber > identity.tcbEvaluationDataNumber ||
                existingIdentity.issueDateTimestamp > identity.issueDateTimestamp;
            if (outOfDate) {
                revert Enclave_Id_Out_Of_Date();
            }
        }

        reqData = abi.encode(identity, enclaveIdentityObj.identityStr, enclaveIdentityObj.signature);
    }

    /**
     * @notice validates IdentityString is signed by Intel TCB Signing Cert
     */
    function _validateQeIdentity(EnclaveIdentityJsonObj calldata enclaveIdentityObj) private view {
        bytes memory signingDer = _fetchDataFromResolver(Pcs.PCS_KEY(CA.SIGNING, false), false);

        // Validate signature
        bool sigVerified =
            verifySignature(sha256(bytes(enclaveIdentityObj.identityStr)), enclaveIdentityObj.signature, signingDer);

        if (!sigVerified) {
            revert Invalid_TCB_Cert_Signature();
        }
    }
}
