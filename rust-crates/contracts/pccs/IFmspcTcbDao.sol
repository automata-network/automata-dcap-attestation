// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

enum TcbId {
    /// the "id" field is absent from TCBInfo V2
    /// which defaults TcbId to SGX
    /// since TDX TCBInfos are only included in V3 or above
    SGX,
    TDX
}

/**
 * @dev This is a simple representation of the TCBInfo.json in string as a Solidity object.
 * @param tcbInfo: tcbInfoJson.tcbInfo string object body
 * @param signature The signature to be passed as bytes array
 */
struct TcbInfoJsonObj {
    string tcbInfoStr;
    bytes signature;
}

/// @dev Solidity object representing TCBInfo.json excluding TCBLevels
struct TcbInfoBasic {
    /// the name "tcbType" can be confusing/misleading
    /// as the tcbType referred here in this struct is the type
    /// of TCB level composition that determines TCB level comparison logic
    /// It is not the same as the "type" parameter passed as an argument to the
    /// getTcbInfo() API method described in Section 4.2.3 of the Intel PCCS Design Document
    /// Instead, getTcbInfo() "type" argument should be checked against the "id" value of this struct
    /// which represents the TEE type for the given TCBInfo
    uint8 tcbType;
    TcbId id;
    uint32 version;
    uint64 issueDate;
    uint64 nextUpdate;
    uint32 evaluationDataNumber;
    bytes6 fmspc;
    bytes2 pceid;
}

struct TCBLevelsObj {
    uint16 pcesvn;
    uint8[] sgxComponentCpuSvns;
    uint8[] tdxComponentCpuSvns;
    uint64 tcbDateTimestamp;
    TCBStatus status;
    string[] advisoryIDs;
}

struct TDXModule {
    bytes mrsigner; // 48 bytes
    bytes8 attributes;
    bytes8 attributesMask;
}

struct TDXModuleIdentity {
    string id;
    bytes8 attributes;
    bytes8 attributesMask;
    bytes mrsigner; // 48 bytes
    TDXModuleTCBLevelsObj[] tcbLevels;
}

struct TDXModuleTCBLevelsObj {
    uint8 isvsvn;
    uint64 tcbDateTimestamp;
    TCBStatus status;
}

enum TCBStatus {
    OK,
    TCB_SW_HARDENING_NEEDED,
    TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED,
    TCB_CONFIGURATION_NEEDED,
    TCB_OUT_OF_DATE,
    TCB_OUT_OF_DATE_CONFIGURATION_NEEDED,
    TCB_REVOKED,
    TCB_UNRECOGNIZED
}

interface IFmspcTcbDao {
    function getTcbInfo(uint256 tcbType, string calldata fmspc, uint256 version)
        external
        view
        returns (TcbInfoJsonObj memory tcbObj);

    function getTcbIssuerChain() external view returns (bytes memory signingCert, bytes memory rootCert);

    function upsertFmspcTcb(TcbInfoJsonObj calldata tcbInfoObj) external returns (bytes32 attestationId);
}
