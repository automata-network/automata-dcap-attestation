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

    event SetCallerAuthorization(address caller, bool authorized);
    event UpdateCallerRestriction(bool restricted);
    event UpdateConfig(
        address qeid, address fmspcTcb, address pcs, address pck, address x509, address x509Crl, address tcbHelper
    );

    // Reverts for missing collaterals

    // 0a2a9142
    error QEIdentityExpiredOrNotFound(EnclaveId id, uint256 quoteVersion);
    // 343385cf
    error FmspcTcbExpiredOrNotFound(TcbId id, uint256 tcbVersion);
    // cc16ebed
    error CertExpiredOrNotFound(CA ca);
    // 482b7129
    error CrlExpiredOrNotFound(CA ca);
    // e2990eed
    error PckNotFound();
    // ee90c468
    error Forbidden();

    function setAuthorized(address caller, bool authorized) external onlyOwner {
        _authorized[caller] = authorized;
        emit SetCallerAuthorization(caller, authorized);
    }

    function enableCallerRestriction() external onlyOwner {
        _isCallerRestricted = true;
        emit UpdateCallerRestriction(true);
    }

    function disableCallerRestriction() external onlyOwner {
        _isCallerRestricted = false;
        emit UpdateCallerRestriction(false);
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

        emit UpdateConfig(_qeid, _fmspcTcb, _pcs, _pck, _x509, _x509Crl, _tcbHelper);
    }

    function getQeIdentity(EnclaveId id, uint256 quoteVersion)
        external
        view
        override
        onlyAuthorized
        returns (IdentityObj memory identity)
    {
        EnclaveIdentityDao enclaveIdDao = EnclaveIdentityDao(qeIdDaoAddr);
        bytes32 key = enclaveIdDao.ENCLAVE_ID_KEY(uint256(id), quoteVersion);
        if (_loadDataIfNotExpired(key, qeIdDaoAddr, block.timestamp)) {
            bytes memory data = enclaveIdDao.getAttestedData(key);
            (identity,) = abi.decode(data, (IdentityObj, EnclaveIdentityJsonObj));
        } else {
            revert QEIdentityExpiredOrNotFound(id, quoteVersion);
        }
    }

    function getQeIdentityContentHash(EnclaveId id, uint256 quoteVersion)
        external
        view
        override
        returns (bytes32 contentHash)
    {
        EnclaveIdentityDao enclaveIdDao = EnclaveIdentityDao(qeIdDaoAddr);
        bytes32 key = enclaveIdDao.ENCLAVE_ID_KEY(uint256(id), quoteVersion);
        contentHash = enclaveIdDao.getIdentityContentHash(key);
    }

    function getFmspcTcbV2(bytes6 fmspc)
        external
        view
        override
        onlyAuthorized
        returns (TCBLevelsObj[] memory tcbLevelsV2)
    {
        FmspcTcbDao tcbDao = FmspcTcbDao(fmspcTcbDaoAddr);
        bytes32 key = tcbDao.FMSPC_TCB_KEY(uint8(TcbId.SGX), fmspc, 2);
        if (_loadDataIfNotExpired(key, fmspcTcbDaoAddr, block.timestamp)) {
            TcbInfoBasic memory tcbInfo;
            bytes memory data = tcbDao.getAttestedData(key);
            bytes memory encodedLevels;
            (tcbInfo, encodedLevels,) = abi.decode(data, (TcbInfoBasic, bytes, TcbInfoJsonObj));
            tcbLevelsV2 = _decodeTcbLevels(encodedLevels);
        } else {
            revert FmspcTcbExpiredOrNotFound(TcbId.SGX, 2);
        }
    }

    function getFmspcTcbV3(TcbId id, bytes6 fmspc)
        external
        view
        override
        onlyAuthorized
        returns (
            TCBLevelsObj[] memory tcbLevelsV3,
            TDXModule memory tdxModule,
            TDXModuleIdentity[] memory tdxModuleIdentities
        )
    {
        FmspcTcbDao tcbDao = FmspcTcbDao(fmspcTcbDaoAddr);
        bytes32 key = tcbDao.FMSPC_TCB_KEY(uint8(id), fmspc, 3);
        if (_loadDataIfNotExpired(key, fmspcTcbDaoAddr, block.timestamp)) {
            TcbInfoBasic memory tcbInfo;
            bytes memory data = tcbDao.getAttestedData(key);
            bytes memory encodedLevels;
            bytes memory encodedTdxModuleIdentities;
            (tcbInfo, tdxModule, encodedTdxModuleIdentities, encodedLevels,) =
                abi.decode(data, (TcbInfoBasic, TDXModule, bytes, bytes, TcbInfoJsonObj));
            tcbLevelsV3 = _decodeTcbLevels(encodedLevels);
            if (encodedTdxModuleIdentities.length > 0) {
                tdxModuleIdentities = _decodeTdxModuleIdentities(encodedTdxModuleIdentities);
            }
        } else {
            revert FmspcTcbExpiredOrNotFound(id, 3);
        }
    }

    function getFmspcTcbContentHash(TcbId id, bytes6 fmspc, uint32 version) external view override returns (bytes32) {
        FmspcTcbDao tcbDao = FmspcTcbDao(fmspcTcbDaoAddr);
        bytes32 key = tcbDao.FMSPC_TCB_KEY(uint8(id), fmspc, version);
        return tcbDao.getTcbInfoContentHash(key);
    }

    /**
     * @notice no expiration check performed
     */
    function getPckCert(
        string calldata qeid,
        string calldata platformCpuSvn,
        string calldata platformPceSvn,
        string calldata pceid
    ) external view override onlyAuthorized returns (bytes memory pckDer) {
        PckDao pckDao = PckDao(pckDaoAddr);
        pckDer = pckDao.getCert(qeid, platformCpuSvn, platformPceSvn, pceid);
        if (pckDer.length == 0) {
            revert PckNotFound();
        }
    }

    function getCert(CA ca) external view override onlyAuthorized returns (bytes memory x509Der) {
        x509Der = _getPcsAttestationData(ca, false, block.timestamp);
    }

    function getCrl(CA ca) external view override onlyAuthorized returns (bytes memory x509CrlDer) {
        x509CrlDer = _getPcsAttestationData(ca, true, block.timestamp);
    }

    function getCertHash(CA ca) external view override onlyAuthorized returns (bytes32 hash) {
        hash = _getPcsHash(ca, false, block.timestamp);
    }

    function getCrlHash(CA ca) external view override onlyAuthorized returns (bytes32 hash) {
        hash = _getPcsHash(ca, true, block.timestamp);
    }

    function getCertHashWithTimestamp(CA ca, uint64 timestamp) external view override returns (bytes32 hash) {
        hash = _getPcsHash(ca, false, timestamp);
    }

    function getCrlHashWithTimestamp(CA ca, uint64 timestamp) external view override returns (bytes32 hash) {
        hash = _getPcsHash(ca, true, timestamp);
    }

    function _decodeTcbLevels(bytes memory encodedTcbLevels) private view returns (TCBLevelsObj[] memory tcbLevels) {
        FmspcTcbHelper fmspcTcbHelper = FmspcTcbHelper(fmspcTcbHelperAddr);
        bytes[] memory encodedTcbLevelsArr = abi.decode(encodedTcbLevels, (bytes[]));
        uint256 n = encodedTcbLevelsArr.length;
        tcbLevels = new TCBLevelsObj[](n);
        for (uint256 i = 0; i < n;) {
            tcbLevels[i] = fmspcTcbHelper.tcbLevelsObjFromBytes(encodedTcbLevelsArr[i]);
            unchecked {
                i++;
            }
        }
    }

    function _decodeTdxModuleIdentities(bytes memory encodedTdxModuleIdentities)
        private
        view
        returns (TDXModuleIdentity[] memory tdxModuleIdentities)
    {
        FmspcTcbHelper fmspcTcbHelper = FmspcTcbHelper(fmspcTcbHelperAddr);
        bytes[] memory encodedTdxModuleIdentitiesArr = abi.decode(encodedTdxModuleIdentities, (bytes[]));
        uint256 n = encodedTdxModuleIdentitiesArr.length;
        tdxModuleIdentities = new TDXModuleIdentity[](n);
        for (uint256 i = 0; i < n;) {
            tdxModuleIdentities[i] = fmspcTcbHelper.tdxModuleIdentityFromBytes(encodedTdxModuleIdentitiesArr[i]);
            unchecked {
                i++;
            }
        }
    }

    function _getPcsAttestationData(CA ca, bool crl, uint256 timestamp) private view returns (bytes memory ret) {
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        bytes32 key = pcsDao.PCS_KEY(ca, crl);
        if (_loadDataIfNotExpired(key, pcsDaoAddr, timestamp)) {
            ret = pcsDao.getAttestedData(key);
        } else {
            if (crl) {
                revert CrlExpiredOrNotFound(ca);
            } else {
                revert CertExpiredOrNotFound(ca);
            }
        }
    }

    function _getPcsHash(CA ca, bool crl, uint256 timestamp) private view returns (bytes32 hash) {
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        bytes32 key = pcsDao.PCS_KEY(ca, crl);
        if (_loadDataIfNotExpired(key, pcsDaoAddr, timestamp)) {
            hash = pcsDao.getCollateralHash(key);
        } else {
            if (crl) {
                revert CrlExpiredOrNotFound(ca);
            } else {
                revert CertExpiredOrNotFound(ca);
            }
        }
    }

    function _loadDataIfNotExpired(bytes32 key, address dao, uint256 timestamp) private view returns (bool valid) {
        bytes4 COLLATERAL_VALIDITY_SELECTOR = 0x3e960426;
        (bool success, bytes memory ret) = dao.staticcall(abi.encodeWithSelector(COLLATERAL_VALIDITY_SELECTOR, key));
        require(success, "Failed to determine collateral validity");
        if (ret.length > 0) {
            (uint64 issuedAt, uint64 expiredAt) = abi.decode(ret, (uint64, uint64));
            valid = timestamp >= issuedAt || timestamp <= expiredAt;
        }
    }
}
