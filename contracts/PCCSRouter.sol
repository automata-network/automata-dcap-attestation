//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IPCCSRouter.sol";

import {Ownable} from "solady/auth/Ownable.sol";
import {EnclaveIdentityDao} from "@automata-network/on-chain-pccs/bases/EnclaveIdentityDao.sol";
import {FmspcTcbDao} from "@automata-network/on-chain-pccs/bases/FmspcTcbDao.sol";
import {PcsDao} from "@automata-network/on-chain-pccs/bases/PcsDao.sol";
import {PckDao} from "@automata-network/on-chain-pccs/bases/PckDao.sol";

/**
 * @title Automata PCCS Router
 * @dev contracts wanting to read collaterals from On-Chain PCCS
 * is recommended to use this contract, rather than fetching directly from
 * their respective DAOs.
 * @dev this contract ensures that it is pointing to the most up-to-date PCCS DAOs
 * and all collaterals are to be returned in Solidity "friendlier" types.
 */

contract PCCSRouter is IPCCSRouter, Ownable {
    /// @dev PCCS Router is currently access-controlled
    /// @dev can be disabled using Pausable later when desired
    mapping(address => bool) _authorized;

    bool _isCallerRestricted;

    address public override qeIdDaoAddr;
    address public override fmspcTcbDaoAddr;
    address public override pcsDaoAddr;
    address public override pckDaoAddr;
    address public override pckHelperAddr;
    address public override crlHelperAddr;

    constructor(address _qeid, address _fmspcTcb, address _pcs, address _pck, address _pckHelper, address _crlHelper) {
        _initializeOwner(msg.sender);
        _setConfig(_qeid, _fmspcTcb, _pcs, _pck, _pckHelper, _crlHelper);

        // allowing eth_call
        _authorized[address(0)] = true;
    }

    // Reverts for missing collaterals

    // a93fad2a
    error QEIdentityNotFound(EnclaveId id, uint256 quoteVersion);
    // eb9cf5a3
    error FmspcTcbNotFound(TcbId id, uint256 tcbVersion);
    // da236293
    error CertNotFound(CA ca);
    // 18c6f762
    error CrlNotFound(CA ca);
    // ee90c468
    error Forbidden();

    function setAuthorized(address caller, bool authorized) external onlyOwner {
        _authorized[caller] = authorized;
    }

    function enableCallerRestriction() external onlyOwner {
        _isCallerRestricted = true;
    }

    function disableCallerRestriction() external onlyOwner {
        _isCallerRestricted = false;
    }

    modifier onlyAuthorized() {
        if (_isCallerRestricted && !_authorized[msg.sender]) {
            revert Forbidden();
        }
        _;
    }

    function setConfig(
        address _qeid,
        address _fmspcTcb,
        address _pcs,
        address _pck,
        address _pckHelper,
        address _crlHelper
    ) external onlyOwner {
        _setConfig(_qeid, _fmspcTcb, _pcs, _pck, _pckHelper, _crlHelper);
    }

    function _setConfig(
        address _qeid,
        address _fmspcTcb,
        address _pcs,
        address _pck,
        address _pckHelper,
        address _crlHelper
    ) private {
        qeIdDaoAddr = _qeid;
        fmspcTcbDaoAddr = _fmspcTcb;
        pcsDaoAddr = _pcs;
        pckDaoAddr = _pck;
        pckHelperAddr = _pckHelper;
        crlHelperAddr = _crlHelper;
    }

    function getQeIdentity(EnclaveId id, uint256 quoteVersion)
        external
        view
        override
        onlyAuthorized
        returns (bool valid, IdentityObj memory identity)
    {
        EnclaveIdentityDao enclaveIdDao = EnclaveIdentityDao(qeIdDaoAddr);
        bytes32 key = enclaveIdDao.ENCLAVE_ID_KEY(uint256(id), quoteVersion);
        bytes memory data = enclaveIdDao.getAttestedData(key);
        valid = data.length > 0;
        if (valid) {
            (identity,,) = abi.decode(data, (IdentityObj, string, bytes));
        } else {
            revert QEIdentityNotFound(id, quoteVersion);
        }
    }

    function getFmspcTcbV2(bytes6 fmspc)
        external
        view
        override
        onlyAuthorized
        returns (bool valid, TCBLevelsObj[] memory tcbLevelsV2)
    {
        FmspcTcbDao tcbDao = FmspcTcbDao(fmspcTcbDaoAddr);
        bytes32 key = tcbDao.FMSPC_TCB_KEY(uint8(TcbId.SGX), fmspc, 2);
        TcbInfoBasic memory tcbInfo;
        bytes memory data = tcbDao.getAttestedData(key);
        valid = data.length > 0;
        if (valid) {
            (tcbInfo, tcbLevelsV2,,) = abi.decode(data, (TcbInfoBasic, TCBLevelsObj[], string, bytes));
        } else {
            revert FmspcTcbNotFound(TcbId.SGX, 2);
        }
    }

    function getFmspcTcbV3(TcbId id, bytes6 fmspc)
        external
        view
        override
        onlyAuthorized
        returns (
            bool valid,
            TCBLevelsObj[] memory tcbLevelsV3,
            TDXModule memory tdxModule,
            TDXModuleIdentity[] memory tdxModuleIdentities
        )
    {
        FmspcTcbDao tcbDao = FmspcTcbDao(fmspcTcbDaoAddr);
        bytes32 key = tcbDao.FMSPC_TCB_KEY(uint8(id), fmspc, 3);
        TcbInfoBasic memory tcbInfo;
        bytes memory data = tcbDao.getAttestedData(key);
        valid = data.length > 0;
        if (valid) {
            (tcbInfo, tdxModule, tdxModuleIdentities, tcbLevelsV3,,) =
                abi.decode(data, (TcbInfoBasic, TDXModule, TDXModuleIdentity[], TCBLevelsObj[], string, bytes));
        } else {
            revert FmspcTcbNotFound(id, 3);
        }
    }

    function getPckCert(
        string calldata qeid,
        string calldata platformCpuSvn,
        string calldata platformPceSvn,
        string calldata pceid
    ) external view override onlyAuthorized returns (bool success, bytes memory pckDer) {
        PckDao pckDao = PckDao(pckDaoAddr);
        pckDer = pckDao.getCert(qeid, platformCpuSvn, platformPceSvn, pceid);
        success = pckDer.length > 0;
    }

    function getCert(CA ca) external view override onlyAuthorized returns (bool success, bytes memory x509Der) {
        (success, x509Der) = _getPcsAttestationData(ca, false);
    }

    function getCrl(CA ca) external view override onlyAuthorized returns (bool success, bytes memory x509CrlDer) {
        (success, x509CrlDer) = _getPcsAttestationData(ca, true);
    }

    function getCertHash(CA ca) external view override onlyAuthorized returns (bool success, bytes32 hash) {
        (success, hash) = _getPcsHash(ca, false);
    }

    function getCrlHash(CA ca) external view override onlyAuthorized returns (bool success, bytes32 hash) {
        (success, hash) = _getPcsHash(ca, true);
    }

    function _getPcsAttestationData(CA ca, bool crl) private view returns (bool valid, bytes memory ret) {
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        ret = pcsDao.getAttestedData(pcsDao.PCS_KEY(ca, crl));
        valid = ret.length > 0;
        if (!valid) {
            if (crl) {
                revert CrlNotFound(ca);
            } else {
                revert CertNotFound(ca);
            }
        }
    }

    function _getPcsHash(CA ca, bool crl) private view returns (bool valid, bytes32 hash) {
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        hash = pcsDao.getCollateralHash(pcsDao.PCS_KEY(ca, crl));
        valid = hash != bytes32(0);
        if (!valid) {
            if (crl) {
                revert CrlNotFound(ca);
            } else {
                revert CertNotFound(ca);
            }
        }
    }
}
