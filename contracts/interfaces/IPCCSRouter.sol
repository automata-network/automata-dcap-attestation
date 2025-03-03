//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {IdentityObj, EnclaveId} from "@automata-network/on-chain-pccs/helpers/EnclaveIdentityHelper.sol";
import {
    TCBLevelsObj,
    TcbInfoBasic,
    TcbId,
    TDXModule,
    TDXModuleIdentity
} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";
import {CA} from "@automata-network/on-chain-pccs/bases/PcsDao.sol";

/**
 * @title PCCS Router Interface
 * @notice The PCCS Router is a central contract that serves all other contracts in the network
 * to fetch collaterals from the On Chain PCCS
 */

interface IPCCSRouter {
    function qeIdDaoAddr() external view returns (address);

    function fmspcTcbDaoAddr() external view returns (address);

    function pckDaoAddr() external view returns (address);

    function pcsDaoAddr() external view returns (address);

    function pckHelperAddr() external view returns (address);

    function crlHelperAddr() external view returns (address);

    function fmspcTcbHelperAddr() external view returns (address);

    function getQeIdentity(EnclaveId id, uint256 quoteVersion) external view returns (bool, IdentityObj memory);

    function getQeIdentityContentHash(EnclaveId id, uint256 version) external view returns (bytes32);

    function getFmspcTcbV2(bytes6 fmspc) external view returns (bool, TCBLevelsObj[] memory);

    function getFmspcTcbV3(TcbId id, bytes6 fmspc)
        external
        view
        returns (bool, TCBLevelsObj[] memory, TDXModule memory, TDXModuleIdentity[] memory);

    function getFmspcTcbContentHash(TcbId id, bytes6 fmspc, uint32 version) external view returns (bytes32);

    function getPckCert(
        string calldata qeid,
        string calldata platformCpuSvn,
        string calldata platformPceSvn,
        string calldata pceid
    ) external view returns (bool, bytes memory);

    function getCert(CA ca) external view returns (bool, bytes memory);

    function getCrl(CA ca) external view returns (bool, bytes memory);

    function getCertHash(CA ca) external view returns (bool, bytes32);

    function getCrlHash(CA ca) external view returns (bool, bytes32);

    // *withTimestamp() methods to check collateral expiration status based on the provided timestamp
    function getCertHashWithTimestamp(CA ca, uint64 timestamp) external view returns (bytes32);

    function getCrlHashWithTimestamp(CA ca, uint64 timestamp) external view returns (bytes32);
}
