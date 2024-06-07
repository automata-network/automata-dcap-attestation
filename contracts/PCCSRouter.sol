//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IPCCSRouter.sol";

import {Ownable} from "solady/auth/Ownable.sol";

import {EnclaveIdentityDao} from "@automata-network/on-chain-pccs/dao/EnclaveIdentityDao.sol";
import {FmspcTcbDao} from "@automata-network/on-chain-pccs/dao/FmspcTcbDao.sol";
import {PcsDao} from "@automata-network/on-chain-pccs/dao/PcsDao.sol";

contract PCCSRouter is IPCCSRouter, Ownable {
    address public override qeIdDaoAddr;
    address public override fmspcTcbDaoAddr;
    address public override pcsDaoAddr;
    address public override pckHelperAddr;
    address public override crlHelperAddr;

    constructor(address _qeid, address _fmspcTcb, address _pcs, address _pckHelper, address _crlHelper) {
        _initializeOwner(msg.sender);
        _setConfig(_qeid, _fmspcTcb, _pcs, _pckHelper, _crlHelper);
    }

    error QEIdentityNotFound(EnclaveId id, uint256 quoteVersion);
    error FmspcTcbNotFound(TcbId id, uint256 tcbVersion);
    error CertNotFound(CA ca);
    error CrlNotFound(CA ca);
    error CollateralExpired();

    function setConfig(address _qeid, address _fmspcTcb, address _pcs, address _pckHelper, address _crlHelper)
        external
        onlyOwner
    {
        _setConfig(_qeid, _fmspcTcb, _pcs, _pckHelper, _crlHelper);
    }

    function _setConfig(address _qeid, address _fmspcTcb, address _pcs, address _pckHelper, address _crlHelper)
        private
    {
        qeIdDaoAddr = _qeid;
        fmspcTcbDaoAddr = _fmspcTcb;
        pcsDaoAddr = _pcs;
        pckHelperAddr = _pckHelper;
        crlHelperAddr = _crlHelper;
    }

    function getQeIdentity(EnclaveId id, uint256 quoteVersion)
        external
        view
        override
        returns (IdentityObj memory identity)
    {
        bytes32 key = keccak256(abi.encodePacked(uint256(id), uint256(quoteVersion)));
        EnclaveIdentityDao enclaveIdDao = EnclaveIdentityDao(qeIdDaoAddr);
        bytes32 attestationId = enclaveIdDao.enclaveIdentityAttestations(key);
        if (attestationId == bytes32(0)) {
            revert QEIdentityNotFound(id, quoteVersion);
        }
        (, bytes memory data) = abi.decode(enclaveIdDao.getAttestedData(attestationId, false), (bytes32, bytes));
        (identity,,) = abi.decode(data, (IdentityObj, string, bytes));
        bool valid = _checkTimestamp(identity.issueDateTimestamp, identity.nextUpdateTimestamp);
        if (!valid) {
            revert CollateralExpired();
        }
    }

    function getFmspcTcbV2(string calldata fmspc) external view override returns (TCBLevelsObj[] memory tcbLevelsV2) {
        bytes32 key = keccak256(abi.encodePacked(TcbId.SGX, fmspc, uint256(2)));
        FmspcTcbDao tcbDao = FmspcTcbDao(fmspcTcbDaoAddr);
        bytes32 attestationId = tcbDao.fmspcTcbInfoAttestations(key);
        if (attestationId == bytes32(0)) {
            revert FmspcTcbNotFound(TcbId.SGX, 2);
        }
        (, bytes memory data) = abi.decode(tcbDao.getAttestedData(attestationId, false), (bytes32, bytes));
        uint256 issueTimestamp;
        uint256 nextUpdateTimestamp;
        (,, issueTimestamp, nextUpdateTimestamp, tcbLevelsV2,,) =
            abi.decode(data, (uint256, uint256, uint256, uint256, TCBLevelsObj[], string, bytes));
        bool valid = _checkTimestamp(issueTimestamp, nextUpdateTimestamp);
        if (!valid) {
            revert CollateralExpired();
        }
    }

    function getFmspcTcbV3(TcbId id, string calldata fmspc)
        external
        view
        override
        returns (
            TCBLevelsObj[] memory tcbLevelsV3,
            TDXModule memory tdxModule,
            TDXModuleIdentity[] memory tdxModuleIdentities
        )
    {
        bytes32 key = keccak256(abi.encodePacked(id, fmspc, uint256(3)));
        FmspcTcbDao tcbDao = FmspcTcbDao(fmspcTcbDaoAddr);
        bytes32 attestationId = tcbDao.fmspcTcbInfoAttestations(key);
        if (attestationId == bytes32(0)) {
            revert FmspcTcbNotFound(id, 3);
        }
        (, bytes memory data) = abi.decode(tcbDao.getAttestedData(attestationId, false), (bytes32, bytes));
        uint256 issueTimestamp;
        uint256 nextUpdateTimestamp;
        (,,, issueTimestamp, nextUpdateTimestamp, tcbLevelsV3, tdxModule, tdxModuleIdentities,,) = abi.decode(
            data,
            (uint256, string, uint256, uint256, uint256, TCBLevelsObj[], TDXModule, TDXModuleIdentity[], string, bytes)
        );
        bool valid = _checkTimestamp(issueTimestamp, nextUpdateTimestamp);
        if (!valid) {
            revert CollateralExpired();
        }
    }

    function getCert(CA ca) external view override returns (bytes memory x509Der) {
        bytes memory ret = _getPcsAttestationData(ca, false, false);
        (, x509Der) = abi.decode(ret, (bytes32, bytes));
    }

    function getCrl(CA ca) external view override returns (bytes memory x509CrlDer) {
        bytes memory ret = _getPcsAttestationData(ca, false, true);
        (, x509CrlDer) = abi.decode(ret, (bytes32, bytes));
    }

    function getCertHash(CA ca) external view override returns (bytes32 hash) {
        bytes memory ret = _getPcsAttestationData(ca, false, true);
        hash = bytes32(ret);
    }

    function getCrlHash(CA ca) external view override returns (bytes32 hash) {
        bytes memory ret = _getPcsAttestationData(ca, false, true);
        hash = bytes32(ret);
    }

    /// @dev notBefore is synonymous with issueTimestamp
    /// @dev notAfter is synonymous with nextUpdateTimestamp
    function _checkTimestamp(uint256 notBefore, uint256 notAfter) private view returns (bool valid) {
        valid = block.timestamp >= notBefore || block.timestamp <= notAfter;
    }

    function _getPcsAttestationData(CA ca, bool hashOnly, bool crl) private view returns (bytes memory ret) {
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        bytes32 attestationId = crl ? pcsDao.pcsCrlAttestations(ca) : pcsDao.pcsCertAttestations(ca);
        if (attestationId == bytes32(0)) {
            if (crl) {
                revert CrlNotFound(ca);
            } else {
                revert CertNotFound(ca);
            }
        }
        ret = pcsDao.getAttestedData(attestationId, hashOnly);
    }
}
