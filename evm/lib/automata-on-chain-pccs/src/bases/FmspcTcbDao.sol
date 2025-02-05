// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PcsDao} from "./PcsDao.sol";
import {DaoBase} from "./DaoBase.sol";
import {SigVerifyBase} from "./SigVerifyBase.sol";

import {CA} from "../Common.sol";
import {
    FmspcTcbHelper,
    TcbInfoJsonObj,
    TcbId,
    TcbInfoBasic,
    TCBLevelsObj,
    TDXModule,
    TDXModuleIdentity
} from "../helpers/FmspcTcbHelper.sol";

/// @notice the on-chain schema of the attested data is dependent on the version of TCBInfo:
/// @notice For TCBInfoV2, it consists of the ABI-encoded tuple of:
/// @notice (TcbInfoBasic, TCBLevelsObj[], string tcbInfo, bytes signature)
/// @notice For TCBInfoV3, it consists of the abi-encoded tuple of:
/// @notice (TcbInfoBasic, TDXModule, TDXModuleIdentity[], TCBLevelsObj, string tcbInfo, bytes signature)
/// @notice See {{ FmspcTcbHelper.sol }} to learn more about FMSPC TCB related struct definitions.

/**
 * @title FMSPC TCB Data Access Object
 * @notice This contract is heavily inspired by Section 4.2.3 in the Intel SGX PCCS Design Guidelines
 * https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf
 * @dev should extends this contract and use the provided read/write methods to interact with TCBInfo JSON
 * data published on-chain.
 */
abstract contract FmspcTcbDao is DaoBase, SigVerifyBase {
    PcsDao public Pcs;
    FmspcTcbHelper public FmspcTcbLib;

    // first 4 bytes of FMSPC_TCB_MAGIC
    bytes4 constant FMSPC_TCB_MAGIC = 0xbb69b29c;

    // 8de7233f
    error Invalid_TCB_Cert_Signature();
    // bae57649
    error TCB_Expired();
    // 3d78f9f9
    error TCB_Out_Of_Date();

    event UpsertedFmpscTcb(
        uint8 indexed tcbType,
        bytes6 indexed fmspcTcbBytes,
        uint32 indexed version
    );

    constructor(address _resolver, address _p256, address _pcs, address _fmspcHelper, address _x509Helper)
        SigVerifyBase(_p256, _x509Helper)
        DaoBase(_resolver)
    {
        Pcs = PcsDao(_pcs);
        FmspcTcbLib = FmspcTcbHelper(_fmspcHelper);
    }

    /**
     * @notice computes the key that is mapped to the collateral attestation ID
     * @return key = keccak256(type ++ FMSPC ++ version)
     */
    function FMSPC_TCB_KEY(uint8 tcbType, bytes6 fmspc, uint32 version) public pure returns (bytes32 key) {
        key = keccak256(abi.encodePacked(FMSPC_TCB_MAGIC, tcbType, fmspc, version));
    }

    /**
     * @notice Section 4.2.3 (getTcbInfo)
     * @notice Queries TCB Info for the given FMSPC
     * @param tcbType 0: SGX, 1: TDX
     * https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/39989a42bbbb0c968153a47254b6de79a27eb603/QuoteVerification/QVL/Src/AttestationParsers/src/Json/TcbInfo.cpp#L46-L47
     * @param fmspc FMSPC
     * @param version v2 or v3
     * https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/39989a42bbbb0c968153a47254b6de79a27eb603/QuoteVerification/QVL/Src/AttestationParsers/include/SgxEcdsaAttestation/AttestationParsers.h#L241-L248
     * @return tcbObj See {FmspcTcbHelper.sol} to learn more about the structure definition
     */
    function getTcbInfo(uint256 tcbType, string calldata fmspc, uint256 version)
        external
        view
        returns (TcbInfoJsonObj memory tcbObj)
    {
        bytes6 fmspcBytes = bytes6(uint48(_parseUintFromHex(fmspc)));
        bytes memory attestedTcbData =
            _onFetchDataFromResolver(FMSPC_TCB_KEY(uint8(tcbType), fmspcBytes, uint32(version)), false);
        if (attestedTcbData.length > 0) {
            if (version < 3) {
                (,, tcbObj.tcbInfoStr, tcbObj.signature) =
                    abi.decode(attestedTcbData, (TcbInfoBasic, bytes, string, bytes));
            } else {
                (,,,, tcbObj.tcbInfoStr, tcbObj.signature) = abi.decode(
                    attestedTcbData, (TcbInfoBasic, TDXModule, bytes, bytes, string, bytes)
                );
            }
        }
    }

    /**
     * @notice Section 4.2.9 (upsertEnclaveIdentity)
     * @param tcbInfoObj See {FmspcTcbHelper.sol} to learn more about the structure definition
     */
    function upsertFmspcTcb(TcbInfoJsonObj calldata tcbInfoObj) external returns (bytes32 attestationId) {
        _validateTcbInfo(tcbInfoObj);
        (
            bytes memory req, 
            bytes32 key, 
            uint8 tcbId, 
            bytes6 fmspc, 
            uint32 version, 
            uint64 issueDateTimestamp,
            uint32 evaluationDataNumber
        ) = _buildTcbAttestationRequest(tcbInfoObj);
        bytes32 hash = sha256(bytes(tcbInfoObj.tcbInfoStr));
        attestationId = _attestTcb(req, hash, key);
        _storeTcbInfoIssueEvaluation(key, issueDateTimestamp, evaluationDataNumber);
        emit UpsertedFmpscTcb(tcbId, fmspc, version);
    }

    /**
     * @notice Fetches the TCBInfo Issuer Chain
     * @return signingCert - DER encoded Intel TCB Signing Certificate
     * @return rootCert - DER encoded Intel SGX Root CA
     */
    function getTcbIssuerChain() external view returns (bytes memory signingCert, bytes memory rootCert) {
        signingCert = _onFetchDataFromResolver(Pcs.PCS_KEY(CA.SIGNING, false), false);
        rootCert = _onFetchDataFromResolver(Pcs.PCS_KEY(CA.ROOT, false), false);
    }

    /**
     * @notice attests collateral via the Resolver
     * @return attestationId
     */
    function _attestTcb(bytes memory reqData, bytes32 hash, bytes32 key)
        internal
        virtual
        returns (bytes32 attestationId)
    {
        (attestationId,) = resolver.attest(key, reqData, hash);
    }

    /**
     * @notice constructs the TcbInfo.json attestation data
     */
    function _buildTcbAttestationRequest(TcbInfoJsonObj calldata tcbInfoObj)
        private
        view
        returns 
        (
            bytes memory reqData, 
            bytes32 key, 
            uint8 id,
            bytes6 fmspc, 
            uint32 version,
            uint64 issueDateTimestamp,
            uint32 evaluationDataNumber
        )
    {
        TcbInfoBasic memory tcbInfo;

        string memory tcbLevelsString;
        string memory tdxModuleString;
        string memory tdxModuleIdentitiesString;
        (
            tcbInfo, 
            tcbLevelsString, 
            tdxModuleString, 
            tdxModuleIdentitiesString
        ) = FmspcTcbLib.parseTcbString(tcbInfoObj.tcbInfoStr);

        // check expiration before continuing...
        if (block.timestamp < tcbInfo.issueDate || block.timestamp > tcbInfo.nextUpdate) {
            revert TCB_Expired();
        }

        // Make sure new collateral is "newer"
        id = uint8(tcbInfo.id);
        fmspc = tcbInfo.fmspc;
        version = tcbInfo.version;
        key = FMSPC_TCB_KEY(id, fmspc, version);
        (uint64 existingIssueDate, uint32 existingEvaluationDataNumber) = _loadTcbInfoIssueEvaluation(key);
        if (existingIssueDate > 0) {
            /// I don't think there can be a scenario where an existing tcbinfo with a higher evaluation data number
            /// to be issued BEFORE a new tcbinfo with a lower evaluation data number
            bool outOfDate = tcbInfo.evaluationDataNumber < existingEvaluationDataNumber ||
                tcbInfo.issueDate < existingIssueDate;
            if (outOfDate) {
                revert TCB_Out_Of_Date();
            }
        }

        issueDateTimestamp = tcbInfo.issueDate;
        evaluationDataNumber = tcbInfo.evaluationDataNumber;
        TCBLevelsObj[] memory tcbLevels = FmspcTcbLib.parseTcbLevels(tcbInfo.version, tcbLevelsString);
        bytes memory encodedTcbLevels = _encodeTcbLevels(tcbLevels);
        if (tcbInfo.version < 3) {
            reqData = abi.encode(tcbInfo, encodedTcbLevels, tcbInfoObj.tcbInfoStr, tcbInfoObj.signature);
        } else {
            TDXModule memory module;
            TDXModuleIdentity[] memory moduleIdentities;
            bytes memory encodedModuleIdentities;
            if (tcbInfo.id == TcbId.TDX) {
                (module, moduleIdentities) = FmspcTcbLib.parseTcbTdxModules(tdxModuleString, tdxModuleIdentitiesString);
                encodedModuleIdentities = _encodeTdxModuleIdentities(moduleIdentities);
            }
            reqData = abi.encode(tcbInfo, module, encodedModuleIdentities, encodedTcbLevels, tcbInfoObj.tcbInfoStr, tcbInfoObj.signature);
        }
    }

    function _validateTcbInfo(TcbInfoJsonObj calldata tcbInfoObj) private view {
        // Get TCB Signing Cert
        bytes memory signingDer = _fetchDataFromResolver(Pcs.PCS_KEY(CA.SIGNING, false), false);
       
        // Validate signature
        bool sigVerified = verifySignature(sha256(bytes(tcbInfoObj.tcbInfoStr)), tcbInfoObj.signature, signingDer);

        if (!sigVerified) {
            revert Invalid_TCB_Cert_Signature();
        }
    }

    function _encodeTcbLevels(TCBLevelsObj[] memory tcbLevels) private view returns (bytes memory encoded) {
        uint256 n = tcbLevels.length;
        bytes[] memory arr = new bytes[](n);

        for (uint256 i = 0; i < n;) {
            arr[i] = FmspcTcbLib.tcbLevelsObjToBytes(tcbLevels[i]);
            
            unchecked {
                i++;
            }
        }

        encoded = abi.encode(arr);
    }

    function _encodeTdxModuleIdentities(TDXModuleIdentity[] memory tdxModuleIdentities) private view returns (bytes memory encoded) {
        uint256 n = tdxModuleIdentities.length;
        bytes[] memory arr = new bytes[](n);

        for (uint256 i = 0; i < n;) {
            arr[i] = FmspcTcbLib.tdxModuleIdentityToBytes(tdxModuleIdentities[i]);

            unchecked {
                i++;
            }
        }

        encoded = abi.encode(arr);
    }

    /// @dev for the time being, we will require a method to "cache" the tcbinfo issued timestamp
    /// @dev and the evaluation data number
    /// @dev this reduces the amount of data to read, when performing the rollback check
    /// @dev the functions defined below can be overriden by the inheriting contract

    function _storeTcbInfoIssueEvaluation(bytes32 tcbKey, uint64 issueDateTimestamp, uint32 evaluationDataNumber) internal virtual;

    function _loadTcbInfoIssueEvaluation(bytes32 tcbKey) internal view virtual returns (uint64 issueDateTimestamp, uint32 evaluationDataNumber);
}
