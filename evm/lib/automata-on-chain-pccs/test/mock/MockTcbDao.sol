// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../../src/bases/FmspcTcbDao.sol";
import "../../src/interfaces/IDaoAttestationResolver.sol";

import "forge-std/console.sol";

contract MockTcbDao is FmspcTcbDao {

    constructor(address _resolver, address _p256, address _pcs, address _fmspcHelper, address _x509Helper)
        FmspcTcbDao(_resolver, _p256, _pcs, _fmspcHelper, _x509Helper)
    {}

    function getFmspcTcbV2(bytes6 fmspc)
        external
        view
        returns (bool valid, TCBLevelsObj[] memory tcbLevelsV2)
    {
        bytes32 key = FMSPC_TCB_KEY(uint8(TcbId.SGX), fmspc, 2);
        TcbInfoBasic memory tcbInfo;
        bytes memory data = _fetchDataFromResolver(key, false);
        valid = data.length > 0;
        if (valid) {
            bytes memory encodedLevels;
            (tcbInfo, encodedLevels,,) = abi.decode(data, (TcbInfoBasic, bytes, string, bytes));
            tcbLevelsV2 = _decodeTcbLevels(encodedLevels);
        }
    }

    function getFmspcTcbV3(TcbId id, bytes6 fmspc)
        external
        view
        returns (
            bool valid,
            TCBLevelsObj[] memory tcbLevelsV3,
            TDXModule memory tdxModule,
            TDXModuleIdentity[] memory tdxModuleIdentities
        )
    {
        bytes32 key = FMSPC_TCB_KEY(uint8(id), fmspc, 3);
        TcbInfoBasic memory tcbInfo;
        bytes memory data = _fetchDataFromResolver(key, false);
        valid = data.length > 0;
        if (valid) {
            bytes memory encodedLevels;
            bytes memory encodedTdxModuleIdentities;
            (tcbInfo, tdxModule, encodedTdxModuleIdentities, encodedLevels,,) =
                abi.decode(data, (TcbInfoBasic, TDXModule, bytes, bytes, string, bytes));
            tcbLevelsV3 = _decodeTcbLevels(encodedLevels);
            if (encodedTdxModuleIdentities.length > 0) {
                tdxModuleIdentities = _decodeTdxModuleIdentities(encodedTdxModuleIdentities);
            }
            console.log("tcb levels before optimization length: ", abi.encode(tcbLevelsV3).length);
            console.log("tcb levels after optimization length: ", encodedLevels.length);
            console.log("tdxmodule id tcb levels before optimization length: ", abi.encode(tdxModuleIdentities).length);
            console.log("tdxmodule id tcb levels after optimization length: ", encodedTdxModuleIdentities.length);
        }
    }

    function _decodeTcbLevels(bytes memory encodedTcbLevels) private view returns (TCBLevelsObj[] memory tcbLevels) {
        bytes[] memory encodedTcbLevelsArr = abi.decode(encodedTcbLevels, (bytes[]));
        uint256 n = encodedTcbLevelsArr.length;
        tcbLevels = new TCBLevelsObj[](n);
        for (uint256 i = 0; i < n;) {
            tcbLevels[i] = FmspcTcbLib.tcbLevelsObjFromBytes(encodedTcbLevelsArr[i]);
            unchecked {
                i++;
            }
        }
    }

    function _decodeTdxModuleIdentities(bytes memory encodedTdxModuleIdentities) private view returns (TDXModuleIdentity[] memory tdxModuleIdentities) {
        bytes[] memory encodedTdxModuleIdentitiesArr = abi.decode(encodedTdxModuleIdentities, (bytes[]));
        uint256 n = encodedTdxModuleIdentitiesArr.length;
        tdxModuleIdentities = new TDXModuleIdentity[](n);
        for (uint256 i = 0; i < n;) {
            tdxModuleIdentities[i] = FmspcTcbLib.tdxModuleIdentityFromBytes(encodedTdxModuleIdentitiesArr[i]);
            unchecked {
                i++;
            }
        }
    }

    function _storeTcbInfoIssueEvaluation(bytes32 tcbKey, uint64 issueDateTimestamp, uint32 evaluationDataNumber) internal override {
        bytes32 tcbIssueEvaluationKey = _computeTcbIssueEvaluationKey(tcbKey);
        uint256 slot = (uint256(issueDateTimestamp) << 2 ** 128) | evaluationDataNumber;
        resolver.attest(tcbIssueEvaluationKey, abi.encode(slot), bytes32(0));
    }
    
    function _loadTcbInfoIssueEvaluation(bytes32 tcbKey) internal view override returns (uint64 issueDateTimestamp, uint32 evaluationDataNumber) {
        bytes32 tcbIssueEvaluationKey = _computeTcbIssueEvaluationKey(tcbKey);
        bytes memory data = resolver.readAttestation(resolver.collateralPointer(tcbIssueEvaluationKey));
        if (data.length > 0) {
            (uint256 slot) = abi.decode(data, (uint256));
            issueDateTimestamp = uint64(slot >> 128);
            evaluationDataNumber = uint32(slot);
        }
    }

    function _computeTcbIssueEvaluationKey(bytes32 key) private pure returns (bytes32 ret) {
        ret = keccak256(abi.encodePacked(key, "tcbIssueEvaluation"));
    }
}