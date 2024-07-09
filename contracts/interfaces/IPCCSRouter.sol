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

interface IPCCSRouter {
    function qeIdDaoAddr() external view returns (address);

    function fmspcTcbDaoAddr() external view returns (address);

    function pcsDaoAddr() external view returns (address);

    function pckHelperAddr() external view returns (address);

    function crlHelperAddr() external view returns (address);

    function getQeIdentity(EnclaveId id, uint256 quoteVersion)
        external
        view
        returns (bool success, IdentityObj memory);

    function getFmspcTcbV2(bytes6 fmspc) external view returns (bool success, TCBLevelsObj[] memory);

    function getFmspcTcbV3(TcbId id, bytes6 fmspc)
        external
        view
        returns (bool success, TCBLevelsObj[] memory, TDXModule memory, TDXModuleIdentity[] memory);

    function getCert(CA ca) external view returns (bool success, bytes memory);

    function getCrl(CA ca) external view returns (bool success, bytes memory);

    function getCertHash(CA ca) external view returns (bool success, bytes32);

    function getCrlHash(CA ca) external view returns (bool success, bytes32);
}
