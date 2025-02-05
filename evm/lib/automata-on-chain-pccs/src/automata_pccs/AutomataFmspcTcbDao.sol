// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FmspcTcbDao, PcsDao, DaoBase} from "../bases/FmspcTcbDao.sol";
import {AutomataDaoBase} from "./shared/AutomataDaoBase.sol";

contract AutomataFmspcTcbDao is AutomataDaoBase, FmspcTcbDao {
    constructor(address _storage, address _p256, address _pcs, address _fmspcHelper, address _x509Helper)
        FmspcTcbDao(_storage, _p256, _pcs, _fmspcHelper, _x509Helper)
    {}

    function _onFetchDataFromResolver(bytes32 key, bool hash)
        internal
        view
        override(AutomataDaoBase, DaoBase)
        returns (bytes memory data)
    {
        data = super._onFetchDataFromResolver(key, hash);
    }

    /// @dev submit tcb issue date timestamp and evaluation data number as a separate attestation
    /// TEMP: it is not the most efficient approach, since it's storing duplicate data
    /// @dev if i could extract the required info directly from the attestation,
    /// this method will no longer be needed
    /// @dev this is a good TODO for future optimization
    function _storeTcbInfoIssueEvaluation(bytes32 tcbKey, uint64 issueDateTimestamp, uint32 evaluationDataNumber) internal override {
        bytes32 tcbIssueEvaluationKey = _computeTcbIssueEvaluationKey(tcbKey);
        uint256 slot = (uint256(issueDateTimestamp) << 128) | evaluationDataNumber;
        resolver.attest(tcbIssueEvaluationKey, abi.encode(slot), bytes32(0));
    }

    /// TEMP it just reads from the separate attestation for now
    /// @dev we will have to come up with hacky low-level storage reads
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
