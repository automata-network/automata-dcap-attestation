//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IPCCSRouter.sol";

import {Ownable} from "solady/auth/Ownable.sol";
import {EnclaveIdentityDao} from "@automata-network/on-chain-pccs/bases/EnclaveIdentityDao.sol";
import {FmspcTcbDao} from "@automata-network/on-chain-pccs/bases/FmspcTcbDao.sol";
import {PcsDao} from "@automata-network/on-chain-pccs/bases/PcsDao.sol";
import {PckDao} from "@automata-network/on-chain-pccs/bases/PckDao.sol";
import {FmspcTcbHelper} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";

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
    address public override fmspcTcbHelperAddr;

    constructor(
        address owner,
        address _qeid, 
        address _fmspcTcb, 
        address _pcs, 
        address _pck,
        address _x509,
        address _x509Crl,
        address _tcbHelper
    ) {
        _initializeOwner(owner);
        _setConfig(_qeid, _fmspcTcb, _pcs, _pck, _x509, _x509Crl, _tcbHelper);

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
        address _x509,
        address _x509Crl,
        address _tcbHelper
    ) external onlyOwner {
        _setConfig(_qeid, _fmspcTcb, _pcs, _pck, _x509, _x509Crl, _tcbHelper);
    }

    function _setConfig(
        address _qeid, 
        address _fmspcTcb, 
        address _pcs, 
        address _pck,
        address _x509,
        address _x509Crl,
        address _tcbHelper
    ) private {
        qeIdDaoAddr = _qeid;
        fmspcTcbDaoAddr = _fmspcTcb;
        pcsDaoAddr = _pcs;
        pckDaoAddr = _pck;
        pckHelperAddr = _x509;
        crlHelperAddr = _x509Crl;
        fmspcTcbHelperAddr = _tcbHelper;
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
            bytes memory encodedLevels;
            (tcbInfo, encodedLevels,,) = abi.decode(data, (TcbInfoBasic, bytes, string, bytes));
            tcbLevelsV2 = _decodeTcbLevels(encodedLevels);
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
            bytes memory encodedLevels;
            bytes memory encodedTdxModuleIdentities;
            (tcbInfo, tdxModule, encodedTdxModuleIdentities, encodedLevels,,) =
                abi.decode(data, (TcbInfoBasic, TDXModule, bytes, bytes, string, bytes));
            tcbLevelsV3 = _decodeTcbLevels(encodedLevels);
            if (encodedTdxModuleIdentities.length > 0) {
                tdxModuleIdentities = _decodeTdxModuleIdentities(encodedTdxModuleIdentities);
            }
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

    function _decodeTcbLevels(bytes memory encodedTcbLevels) private view returns (TCBLevelsObj[] memory tcbLevels) {
        FmspcTcbHelper fmspcTcbHelper = FmspcTcbHelper(fmspcTcbHelperAddr);
        bytes[] memory encodedTcbLevelsArr = abi.decode(encodedTcbLevels, (bytes[]));
        uint256 n = encodedTcbLevelsArr.length;
        tcbLevels = new TCBLevelsObj[](n);
        for (uint256 i = 0; i < n; ) {
            tcbLevels[i] = fmspcTcbHelper.tcbLevelsObjFromBytes(encodedTcbLevelsArr[i]);
            unchecked {
                i++;
            }
        }
    }

    function _decodeTdxModuleIdentities(bytes memory encodedTdxModuleIdentities) private view returns (TDXModuleIdentity[] memory tdxModuleIdentities) {
        FmspcTcbHelper fmspcTcbHelper = FmspcTcbHelper(fmspcTcbHelperAddr);
        bytes[] memory encodedTdxModuleIdentitiesArr = abi.decode(encodedTdxModuleIdentities, (bytes[]));
        uint256 n = encodedTdxModuleIdentitiesArr.length;
        tdxModuleIdentities = new TDXModuleIdentity[](n);
        for (uint256 i = 0; i < n; ) {
            tdxModuleIdentities[i] = fmspcTcbHelper.tdxModuleIdentityFromBytes(encodedTdxModuleIdentitiesArr[i]);
            unchecked {
                i++;
            }
        }
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
