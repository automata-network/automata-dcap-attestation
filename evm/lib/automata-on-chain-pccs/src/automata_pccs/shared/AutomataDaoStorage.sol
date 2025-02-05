// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IDaoAttestationResolver} from "../../interfaces/IDaoAttestationResolver.sol";
import {AutomataTCBManager, EnumerableSet} from "./AutomataTCBManager.sol";

import {Ownable} from "solady/auth/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title Automata PCCS Dao Storage
 * @notice This contract resolves and stores all collateral data internally
 */

contract AutomataDaoStorage is AutomataTCBManager, IDaoAttestationResolver, Pausable, Ownable {
    mapping(address => bool) _authorized_writers;
    mapping(address => bool) _authorized_readers;
    mapping(bytes32 attId => bytes collateral) _db;

    modifier onlyDao(address dao) {
        require(_authorized_writers[dao], "FORBIDDEN");
        _;
    }

    constructor() {
        _initializeOwner(msg.sender);

        // adding address(0) as an authorized_reader to allow eth_call
        _authorized_readers[address(0)] = true;
    }

    function isAuthorizedCaller(address caller) external view returns (bool) {
        return _authorized_readers[caller];
    }

    function setCallerAuthorization(address caller, bool authorized) external onlyOwner {
        _authorized_readers[caller] = authorized;
    }

    function pauseCallerRestriction() external onlyOwner whenNotPaused {
        _pause();
    }

    function unpauseCallerRestriction() external onlyOwner whenPaused {
        _unpause();
    }

    function updateDao(address _pcsDao, address _pckDao, address _fmspcTcbDao, address _enclaveIdDao)
        external
        onlyOwner
    {
        _updateDao(_pcsDao, _pckDao, _fmspcTcbDao, _enclaveIdDao);
    }

    function revokeDao(address revoked) external onlyOwner {
        _authorized_writers[revoked] = false;
    }

    function collateralPointer(bytes32 key) external pure override returns (bytes32 collateralAttId) {
        collateralAttId = _computeAttestationId(key, false);
    }

    function collateralHashPointer(bytes32 key) external pure override returns (bytes32 collateralHashAttId) {
        collateralHashAttId = _computeAttestationId(key, true);
    }

    function readAttestation(bytes32 attestationId)
        external
        view
        override
        onlyDao(msg.sender)
        returns (bytes memory attData)
    {
        attData = _db[attestationId];
    }

    /**
     * @notice In AutomataDaoStorage, we will simply assign the key as the attestationid of the collateral
     */
    function attest(bytes32 key, bytes calldata attData, bytes32 attDataHash)
        external
        override
        onlyDao(msg.sender)
        returns (bytes32 attestationId, bytes32 hashAttestationid)
    {
        attestationId = _computeAttestationId(key, false);
        _db[attestationId] = attData;

        // this makes storing hash optional
        if (attDataHash != bytes32(0)) {
            hashAttestationid = _computeAttestationId(key, true);
            _db[hashAttestationid] = abi.encodePacked(attDataHash);
        }
    }

    function _updateDao(address _pcsDao, address _pckDao, address _fmspcTcbDao, address _enclaveIdDao) private {
        _authorized_writers[_pcsDao] = true;
        _authorized_writers[_pckDao] = true;
        _authorized_writers[_fmspcTcbDao] = true;
        _authorized_writers[_enclaveIdDao] = true;
    }

    /// Attestation ID Computation
    bytes4 constant DATA_ATTESTATION_MAGIC = 0x54a09e9a;
    bytes4 constant HASH_ATTESTATION_MAGIC = 0x628ab4d2;

    function _computeAttestationId(bytes32 key, bool hash) private pure returns (bytes32 attestationId) {
        bytes32 magic = hash ? HASH_ATTESTATION_MAGIC : DATA_ATTESTATION_MAGIC;
        attestationId = keccak256(abi.encodePacked(magic, key));
    }

    /// TCB Management
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /**
     * @notice forms a mapping between (qeid, pceid) to tcbm
     * @dev called AFTER the qeid, pceid and tcbm are all validated by the same PCK Certificate
     */
    function setTcbm(bytes16 qeid, bytes2 pceid, bytes18 tcbm) external onlyDao(msg.sender) {
        bytes32 k = keccak256(abi.encodePacked(qeid, pceid));
        if (!_tcbmSet[k].contains(bytes32(tcbm))) {
            _tcbmSet[k].add(bytes32(tcbm));
        }
    }

    /**
     * @notice prints out a list of tcbms associated with the given qeid and pceid paired values
     */
    function printTcbmSet(bytes16 qeid, bytes2 pceid) external view returns (bytes18[] memory set) {
        bytes32 k = keccak256(abi.encodePacked(qeid, pceid));
        uint256 n = _tcbmSet[k].length();
        set = new bytes18[](n);
        for (uint256 i = 0; i < n;) {
            set[i] = bytes18(_tcbmSet[k].at(i));
            unchecked {
                i++;
            }
        }
    }

    /**
     * @notice forms a mapping of rawTcb to tcbm
     */
    function setTcbrMapping(bytes32 rawTcbKey, bytes18 tcbm) external onlyDao(msg.sender) {
        _tcbMapping[rawTcbKey] = tcbm;
    }

    function getTcbm(bytes32 rawTcbKey) external view onlyDao(msg.sender) returns (bytes18 tcbm) {
        tcbm = _tcbMapping[rawTcbKey];
    }
}
