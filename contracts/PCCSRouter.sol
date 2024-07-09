//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IPCCSRouter.sol";

import {Ownable} from "solady/auth/Ownable.sol";

import {EnclaveIdentityDao} from "@automata-network/on-chain-pccs/bases/EnclaveIdentityDao.sol";
import {FmspcTcbDao} from "@automata-network/on-chain-pccs/bases/FmspcTcbDao.sol";
import {PcsDao} from "@automata-network/on-chain-pccs/bases/PcsDao.sol";

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

    // events to be monitored (may emit due to missing or expired collaterals)
    // event QEIdentityNotFound(EnclaveId id, uint256 quoteVersion);
    // event QEIdentityExpired(uint256 nextUpdateTimestamp);
    // event FmspcTcbNotFound(TcbId id, uint256 tcbVersion);
    // event FmspcTcbExpired(uint256 nextUpdateTimestamp);
    // event CertNotFound(CA ca);
    // event CrlNotFound(CA ca);

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
        returns (bool valid, IdentityObj memory identity)
    {
        bytes32 key = keccak256(abi.encodePacked(uint256(id), uint256(quoteVersion)));
        EnclaveIdentityDao enclaveIdDao = EnclaveIdentityDao(qeIdDaoAddr);
        bytes32 attestationId = enclaveIdDao.enclaveIdentityAttestations(key);
        if (attestationId == bytes32(0)) {
            // emit QEIdentityNotFound(id, quoteVersion);
            return (false, identity);
        }
        bytes memory data = enclaveIdDao.getAttestedData(attestationId);
        (identity,,) = abi.decode(data, (IdentityObj, string, bytes));
        valid = _checkTimestamp(identity.issueDateTimestamp, identity.nextUpdateTimestamp);
        if (!valid) {
            // emit QEIdentityExpired(identity.nextUpdateTimestamp);
        }
    }

    function getFmspcTcbV2(bytes6 fmspc)
        external
        view
        override
        returns (bool valid, TCBLevelsObj[] memory tcbLevelsV2)
    {
        bytes32 key = keccak256(abi.encodePacked(uint8(TcbId.SGX), fmspc, uint32(2)));
        FmspcTcbDao tcbDao = FmspcTcbDao(fmspcTcbDaoAddr);
        bytes32 attestationId = tcbDao.fmspcTcbInfoAttestations(key);
        if (attestationId == bytes32(0)) {
            // emit FmspcTcbNotFound(TcbId.SGX, 2);
            return (false, tcbLevelsV2);
        }
        TcbInfoBasic memory tcbInfo;
        bytes memory data = tcbDao.getAttestedData(attestationId);
        (tcbInfo, tcbLevelsV2,,) = abi.decode(data, (TcbInfoBasic, TCBLevelsObj[], string, bytes));
        valid = _checkTimestamp(tcbInfo.issueDate, tcbInfo.nextUpdate);
        if (!valid) {
            // emit FmspcTcbExpired(tcbInfo.nextUpdate);
        }
    }

    function getFmspcTcbV3(TcbId id, bytes6 fmspc)
        external
        view
        override
        returns (
            bool valid,
            TCBLevelsObj[] memory tcbLevelsV3,
            TDXModule memory tdxModule,
            TDXModuleIdentity[] memory tdxModuleIdentities
        )
    {
        bytes32 key = keccak256(abi.encodePacked(uint8(id), fmspc, uint32(3)));
        FmspcTcbDao tcbDao = FmspcTcbDao(fmspcTcbDaoAddr);
        bytes32 attestationId = tcbDao.fmspcTcbInfoAttestations(key);
        if (attestationId == bytes32(0)) {
            // emit FmspcTcbNotFound(id, 3);
            return (false, tcbLevelsV3, tdxModule, tdxModuleIdentities);
        }
        TcbInfoBasic memory tcbInfo;
        bytes memory data = tcbDao.getAttestedData(attestationId);
        (tcbInfo, tdxModule, tdxModuleIdentities, tcbLevelsV3,,) =
            abi.decode(data, (TcbInfoBasic, TDXModule, TDXModuleIdentity[], TCBLevelsObj[], string, bytes));
        valid = _checkTimestamp(tcbInfo.issueDate, tcbInfo.nextUpdate);
        if (!valid) {
            // emit FmspcTcbExpired(tcbInfo.nextUpdate);
        }
    }

    function getCert(CA ca) external view override returns (bool success, bytes memory x509Der) {
        (success, x509Der) = _getPcsAttestationData(ca, false);
    }

    function getCrl(CA ca) external view override returns (bool success, bytes memory x509CrlDer) {
        (success, x509CrlDer) = _getPcsAttestationData(ca, true);
    }

    function getCertHash(CA ca) external view override returns (bool success, bytes32 hash) {
        (success, hash) = _getPcsHash(ca, false);
    }

    function getCrlHash(CA ca) external view override returns (bool success, bytes32 hash) {
        (success, hash) = _getPcsHash(ca, true);
    }

    /// @dev notBefore is synonymous with issueTimestamp
    /// @dev notAfter is synonymous with nextUpdateTimestamp
    function _checkTimestamp(uint256 notBefore, uint256 notAfter) private view returns (bool valid) {
        valid = block.timestamp >= notBefore || block.timestamp <= notAfter;
    }

    function _checkPcsAttestation(PcsDao pcsDao, CA ca, bool crl)
        private
        view
        returns (bool valid, bytes32 attestationId)
    {
        attestationId = crl ? pcsDao.pcsCrlAttestations(ca) : pcsDao.pcsCertAttestations(ca);
        valid = attestationId != bytes32(0);
        // if (!valid) {
        //     if (crl) {
        //         emit CrlNotFound(ca);
        //     } else {
        //         emit CertNotFound(ca);
        //     }
        // }
    }

    function _getPcsAttestationData(CA ca, bool crl) private view returns (bool valid, bytes memory ret) {
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        bytes32 attestationId;
        (valid, attestationId) = _checkPcsAttestation(pcsDao, ca, crl);
        ret = pcsDao.getAttestedData(attestationId);
    }

    function _getPcsHash(CA ca, bool crl) private view returns (bool valid, bytes32 hash) {
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        bytes32 attestationId;
        (valid, attestationId) = _checkPcsAttestation(pcsDao, ca, crl);
        hash = pcsDao.getCollateralHash(attestationId);
    }
}
