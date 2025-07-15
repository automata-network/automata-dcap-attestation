//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IPCCSRouter.sol";

import {Ownable} from "solady/auth/Ownable.sol";
import {EnclaveIdentityDao} from "@automata-network/on-chain-pccs/bases/EnclaveIdentityDao.sol";
import {FmspcTcbDao} from "@automata-network/on-chain-pccs/bases/FmspcTcbDao.sol";
import {TcbEvalDao} from "@automata-network/on-chain-pccs/bases/TcbEvalDao.sol";
import {PcsDao} from "@automata-network/on-chain-pccs/bases/PcsDao.sol";
import {PckDao} from "@automata-network/on-chain-pccs/bases/PckDao.sol";
import {FmspcTcbHelper} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";

/**
 * @notice this interface is used for checking the TCB evaluation number to ensure
 * proper configuration of the PCCS Router.
 */
interface IVersionedDao {
    function TCB_EVALUATION_NUMBER() external view returns (uint32);
}

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

    address public override tcbEvalDaoAddr;
    address public override pcsDaoAddr;
    address public override pckDaoAddr;
    address public override pckHelperAddr;
    address public override crlHelperAddr;
    address public override fmspcTcbHelperAddr;

    mapping(uint32 tcbEval => address) public override qeIdDaoVersionedAddr;
    mapping(uint32 tcbEval => address) public override fmspcTcbDaoVersionedAddr;

    constructor(
        address owner,
        address _tcbEval,
        address _pcs,
        address _pck,
        address _x509,
        address _x509Crl,
        address _tcbHelper
    ) {
        _initializeOwner(owner);
        _setConfig(_tcbEval, _pcs, _pck, _x509, _x509Crl, _tcbHelper);

        // allowing eth_call
        _authorized[address(0)] = true;
    }

    modifier checkTcbEval(uint32 tcbEval, address versionedDao) {
        if (versionedDao != address(0)) {
            IVersionedDao dao = IVersionedDao(versionedDao);
            if (dao.TCB_EVALUATION_NUMBER() != tcbEval) {
                revert("Invalid TCB evaluation number");
            }
        }
        _;
    }

    event SetCallerAuthorization(address caller, bool authorized);
    event UpdateCallerRestriction(bool restricted);
    event UpdateConfig(
        address pcs, address pck, address x509, address x509Crl, address tcbHelper
    );
    event UpdateQeIdDaoVersionedAddr(uint32 tcbEval, address addr);
    event UpdateFmspcTcbDaoVersionedAddr(uint32 tcbEval, address addr);

    // Reverts for missing collaterals

    // a78bf21a
    error TcbEvalExpiredOrNotFound(TcbId id);
    // 0a2a9142
    error QEIdentityExpiredOrNotFound(EnclaveId id, uint256 qeIdentityApiVersion);
    // 343385cf
    error FmspcTcbExpiredOrNotFound(TcbId id, uint256 tcbVersion);
    // 5705a2ef
    error TcbEvalNumberMismatch();
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
        address _tcbEval,
        address _pcs,
        address _pck,
        address _x509,
        address _x509Crl,
        address _tcbHelper
    ) external onlyOwner {
        _setConfig(_tcbEval, _pcs, _pck, _x509, _x509Crl, _tcbHelper);
    }

    function setQeIdDaoVersionedAddr(uint32 tcbEval, address addr) external onlyOwner checkTcbEval(tcbEval, addr) {
        qeIdDaoVersionedAddr[tcbEval] = addr;
        emit UpdateQeIdDaoVersionedAddr(tcbEval, addr);
    }

    function setFmspcTcbDaoVersionedAddr(uint32 tcbEval, address addr) external onlyOwner checkTcbEval(tcbEval, addr) {
        fmspcTcbDaoVersionedAddr[tcbEval] = addr;
        emit UpdateFmspcTcbDaoVersionedAddr(tcbEval, addr);
    }

    function _setConfig(
        address _tcbEval,
        address _pcs,
        address _pck,
        address _x509,
        address _x509Crl,
        address _tcbHelper
    ) private {
        tcbEvalDaoAddr = _tcbEval;
        pcsDaoAddr = _pcs;
        pckDaoAddr = _pck;
        pckHelperAddr = _x509;
        crlHelperAddr = _x509Crl;
        fmspcTcbHelperAddr = _tcbHelper;

        emit UpdateConfig(_pcs, _pck, _x509, _x509Crl, _tcbHelper);
    }

    function getEarlyTcbEvaluationDataNumber(TcbId id) external view override onlyAuthorized returns (uint32) {
        TcbEvalDao tcbEvalDao = TcbEvalDao(tcbEvalDaoAddr);
        (bool empty, bool valid) = _loadDataIfNotExpired(tcbEvalDao.TCB_EVAL_KEY(id), tcbEvalDaoAddr, block.timestamp);
        if (!empty && valid) {
            return tcbEvalDao.early(id);
        } else {
            revert TcbEvalExpiredOrNotFound(id);
        }
    }

    function getStandardTcbEvaluationDataNumber(TcbId id) external view override onlyAuthorized returns (uint32) {
        TcbEvalDao tcbEvalDao = TcbEvalDao(tcbEvalDaoAddr);
        (bool empty, bool valid) = _loadDataIfNotExpired(tcbEvalDao.TCB_EVAL_KEY(id), tcbEvalDaoAddr, block.timestamp);
        if (!empty && valid) {
            return tcbEvalDao.standard(id);
        } else {
            revert TcbEvalExpiredOrNotFound(id);
        }
    }

    function getEarlyTcbEvaluationDataNumberWithTimestamp(TcbId id, uint64 timestamp)
        external
        view
        override
        onlyAuthorized
        returns (uint32)
    {
        TcbEvalDao tcbEvalDao = TcbEvalDao(tcbEvalDaoAddr);
        (bool empty, bool valid) = _loadDataIfNotExpired(tcbEvalDao.TCB_EVAL_KEY(id), tcbEvalDaoAddr, timestamp);
        if (!empty && valid) {
            return tcbEvalDao.early(id);
        } else {
            revert TcbEvalExpiredOrNotFound(id);
        }
    }

    function getStandardTcbEvaluationDataNumberWithTimestamp(TcbId id, uint64 timestamp)
        external
        view
        override
        onlyAuthorized
        returns (uint32)
    {
        TcbEvalDao tcbEvalDao = TcbEvalDao(tcbEvalDaoAddr);
        (bool empty, bool valid) = _loadDataIfNotExpired(tcbEvalDao.TCB_EVAL_KEY(id), tcbEvalDaoAddr, timestamp);
        if (!empty && valid) {
            return tcbEvalDao.standard(id);
        } else {
            revert TcbEvalExpiredOrNotFound(id);
        }
    }

    function getQeIdentity(EnclaveId id, uint256 qeIdentityApiVersion, uint32 tcbEval)
        external
        view
        override
        onlyAuthorized
        returns (IdentityObj memory identity)
    {
        // Try versioned DAO first
        address versionedDao = qeIdDaoVersionedAddr[tcbEval];
        if (versionedDao != address(0)) {
            EnclaveIdentityDao versionedEnclaveIdDao = EnclaveIdentityDao(versionedDao);
            bytes32 versionedKey = versionedEnclaveIdDao.ENCLAVE_ID_KEY(uint256(id), qeIdentityApiVersion);
            (bool empty, bool valid) = _loadDataIfNotExpired(versionedKey, versionedDao, block.timestamp);
            if (!empty && valid) {
                bytes memory data = versionedEnclaveIdDao.getAttestedData(versionedKey);
                (identity,) = abi.decode(data, (IdentityObj, EnclaveIdentityJsonObj));
                return identity;
            }
        } else {
            revert QEIdentityExpiredOrNotFound(id, qeIdentityApiVersion);
        }
    }

    function getQeIdentityContentHash(EnclaveId id, uint256 qeIdentityApiVersion, uint32 tcbEval)
        external
        view
        override
        onlyAuthorized
        returns (bytes32 contentHash)
    {
        contentHash = _getQeIdentityContentHash(id, qeIdentityApiVersion, tcbEval, block.timestamp);
    }

    function getQeIdentityContentHashWithTimestamp(
        EnclaveId id,
        uint256 qeIdentityApiVersion,
        uint32 tcbEval,
        uint64 timestamp
    ) external view override onlyAuthorized returns (bytes32 contentHash) {
        contentHash = _getQeIdentityContentHash(id, qeIdentityApiVersion, tcbEval, timestamp);
    }

    function getFmspcTcbV2(bytes6 fmspc, uint32 tcbEval)
        external
        view
        override
        onlyAuthorized
        returns (TCBLevelsObj[] memory tcbLevelsV2)
    {
        // Try versioned DAO first
        address versionedDao = fmspcTcbDaoVersionedAddr[tcbEval];
        if (versionedDao != address(0)) {
            FmspcTcbDao versionedTcbDao = FmspcTcbDao(versionedDao);
            bytes32 versionedKey = versionedTcbDao.FMSPC_TCB_KEY(uint8(TcbId.SGX), fmspc, 2);
            (bool empty, bool valid) = _loadDataIfNotExpired(versionedKey, versionedDao, block.timestamp);
            if (!empty && valid) {
                TcbInfoBasic memory tcbInfo;
                bytes memory data = versionedTcbDao.getAttestedData(versionedKey);
                bytes memory encodedLevels;
                (tcbInfo, encodedLevels,) = abi.decode(data, (TcbInfoBasic, bytes, TcbInfoJsonObj));
                tcbLevelsV2 = _decodeTcbLevels(encodedLevels);
                return tcbLevelsV2;
            }
        } else {
            revert FmspcTcbExpiredOrNotFound(TcbId.SGX, 2);
        }
    }

    function getFmspcTcbV3(TcbId id, bytes6 fmspc, uint32 tcbEval)
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
        // Try versioned DAO first
        address versionedDao = fmspcTcbDaoVersionedAddr[tcbEval];
        if (versionedDao != address(0)) {
            FmspcTcbDao versionedTcbDao = FmspcTcbDao(versionedDao);
            bytes32 versionedKey = versionedTcbDao.FMSPC_TCB_KEY(uint8(id), fmspc, 3);
            (bool empty, bool valid) = _loadDataIfNotExpired(versionedKey, versionedDao, block.timestamp);
            if (!empty && valid) {
                TcbInfoBasic memory tcbInfo;
                bytes memory data = versionedTcbDao.getAttestedData(versionedKey);
                bytes memory encodedLevels;
                bytes memory encodedTdxModuleIdentities;
                (tcbInfo, tdxModule, encodedTdxModuleIdentities, encodedLevels,) =
                    abi.decode(data, (TcbInfoBasic, TDXModule, bytes, bytes, TcbInfoJsonObj));
                tcbLevelsV3 = _decodeTcbLevels(encodedLevels);
                if (encodedTdxModuleIdentities.length > 0) {
                    tdxModuleIdentities = _decodeTdxModuleIdentities(encodedTdxModuleIdentities);
                }
                return (tcbLevelsV3, tdxModule, tdxModuleIdentities);
            }
        } else {
            revert FmspcTcbExpiredOrNotFound(id, 3);
        }
    }

    function getFmspcTcbContentHash(TcbId id, bytes6 fmspc, uint32 version, uint32 tcbEval)
        external
        view
        override
        onlyAuthorized
        returns (bytes32 contentHash)
    {
        contentHash = _getFmspcTcbContentHash(id, fmspc, version, tcbEval, block.timestamp);
    }

    function getFmspcTcbContentHashWithTimestamp(
        TcbId id,
        bytes6 fmspc,
        uint32 version,
        uint32 tcbEval,
        uint64 timestamp
    ) external view override onlyAuthorized returns (bytes32 contentHash) {
        contentHash = _getFmspcTcbContentHash(id, fmspc, version, tcbEval, timestamp);
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

    function getCertHashWithTimestamp(CA ca, uint64 timestamp)
        external
        view
        override
        onlyAuthorized
        returns (bytes32 hash)
    {
        hash = _getPcsHash(ca, false, timestamp);
    }

    function getCrlHashWithTimestamp(CA ca, uint64 timestamp)
        external
        view
        override
        onlyAuthorized
        returns (bytes32 hash)
    {
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
        (bool empty, bool valid) = _loadDataIfNotExpired(key, pcsDaoAddr, timestamp);
        if (!empty && valid) {
            ret = pcsDao.getAttestedData(key);
        } else {
            if (crl) {
                revert CrlExpiredOrNotFound(ca);
            } else {
                revert CertExpiredOrNotFound(ca);
            }
        }
    }

    function _getQeIdentityContentHash(
        EnclaveId id,
        uint256 qeIdentityApiVersion,
        uint32 tcbEval,
        uint256 timestamp
    ) private view returns (bytes32 contentHash) {
        // Try versioned DAO first
        address versionedDao = qeIdDaoVersionedAddr[tcbEval];
        if (versionedDao != address(0)) {
            EnclaveIdentityDao versionedEnclaveIdDao = EnclaveIdentityDao(versionedDao);
            bytes32 versionedKey = versionedEnclaveIdDao.ENCLAVE_ID_KEY(uint256(id), qeIdentityApiVersion);
            (bool empty, bool valid) = _loadDataIfNotExpired(versionedKey, versionedDao, timestamp);
            if (!empty && valid) {
                contentHash = versionedEnclaveIdDao.getIdentityContentHash(versionedKey);
            }
        }

        if (contentHash == bytes32(0)) {
            revert QEIdentityExpiredOrNotFound(id, qeIdentityApiVersion);
        }
    }

    function _getFmspcTcbContentHash(
        TcbId id,
        bytes6 fmspc,
        uint32 version,
        uint32 tcbEval,
        uint256 timestamp
    ) private view returns (bytes32 contentHash) {
        // Try versioned DAO first
        address versionedDao = fmspcTcbDaoVersionedAddr[tcbEval];
        if (versionedDao != address(0)) {
            FmspcTcbDao versionedTcbDao = FmspcTcbDao(versionedDao);
            bytes32 versionedKey = versionedTcbDao.FMSPC_TCB_KEY(uint8(id), fmspc, version);
            (bool empty, bool valid) = _loadDataIfNotExpired(versionedKey, versionedDao, timestamp);
            if (!empty && valid) {
                contentHash = versionedTcbDao.getTcbInfoContentHash(versionedKey);
            }
        }

        if (contentHash == bytes32(0)) {
            revert FmspcTcbExpiredOrNotFound(id, version);
        }
    }

    function _getPcsHash(CA ca, bool crl, uint256 timestamp) private view returns (bytes32 hash) {
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        bytes32 key = pcsDao.PCS_KEY(ca, crl);
        (bool empty, bool valid) = _loadDataIfNotExpired(key, pcsDaoAddr, timestamp);
        if (!empty && valid) {
            hash = pcsDao.getCollateralHash(key);
        } else {
            if (crl) {
                revert CrlExpiredOrNotFound(ca);
            } else {
                revert CertExpiredOrNotFound(ca);
            }
        }
    }

    function _loadDataIfNotExpired(bytes32 key, address dao, uint256 timestamp)
        private
        view
        returns (bool empty, bool valid)
    {
        bytes4 COLLATERAL_VALIDITY_SELECTOR = 0x3e960426;
        (bool success, bytes memory ret) = dao.staticcall(abi.encodeWithSelector(COLLATERAL_VALIDITY_SELECTOR, key));
        require(success, "Failed to determine collateral validity");
        (uint64 issuedAt, uint64 expiredAt) = abi.decode(ret, (uint64, uint64));
        empty = issuedAt == 0 || expiredAt == 0; // neither issuedAt nor expiredAt should be zero
        if (!empty) {
            valid = timestamp >= issuedAt && timestamp <= expiredAt;
        }
    }
}
