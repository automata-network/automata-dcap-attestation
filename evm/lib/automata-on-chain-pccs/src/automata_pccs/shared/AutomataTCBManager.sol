// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

abstract contract AutomataTCBManager {
    /// mapping (keccak256(qeid ++ pceid) => Enumerable tcbm Set)
    mapping(bytes32 => EnumerableSet.Bytes32Set) _tcbmSet;

    /// rawTcbKey = keccak256(qeid ++ pceid ++ rawCpuSvns ++ rawPceSvns)
    mapping(bytes32 rawTcbKey => bytes18 tcbm) _tcbMapping;
}
