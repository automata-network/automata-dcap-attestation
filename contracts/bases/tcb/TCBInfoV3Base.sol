//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    TcbId,
    TDXModule,
    TDXModuleIdentity,
    TDXModuleTCBLevelsObj
} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";
import "./TCBInfoV2Base.sol";

abstract contract TCBInfoV3Base is TCBInfoV2Base {
    using LibString for string;

    uint256 constant TCB_LEVEL_ERROR = type(uint256).max;

    /// @dev Modified from https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp#L129-L181
    function getTDXTcbStatus(TCBLevelsObj[] memory tcbLevels, PCKCertTCB memory pckTcb, bytes16 teeTcbSvn)
        internal
        pure
        returns (bool tdxTcbFound, TCBStatus status, uint256 tcbLevelSelected)
    {
        bool pceSvnIsHigherOrGreater;
        bool cpuSvnsAreHigherOrGreater;
        bool sgxTcbFound;
        TCBStatus sgxStatus;
        for (uint256 i = 0; i < tcbLevels.length; i++) {
            TCBLevelsObj memory current = tcbLevels[i];
            if (!sgxTcbFound) {
                (pceSvnIsHigherOrGreater, cpuSvnsAreHigherOrGreater) = _checkSgxCpuSvns(pckTcb, current);
            }
            if (pceSvnIsHigherOrGreater && cpuSvnsAreHigherOrGreater) {
                sgxTcbFound = true;
                sgxStatus = current.status;
            }
            if (sgxTcbFound && sgxStatus != TCBStatus.TCB_REVOKED) {
                if (teeTcbSvn != bytes16(0)) {
                    if (_isTdxTcbHigherOrEqual(teeTcbSvn, current.tdxSvns)) {
                        tdxTcbFound = true;
                        status = current.status;
                        tcbLevelSelected = i;
                    }
                } else {
                    break;
                }
            } else if (sgxStatus == TCBStatus.TCB_REVOKED) {
                return (false, TCBStatus.TCB_REVOKED, TCB_LEVEL_ERROR);
            }
            if (tdxTcbFound) {
                break;
            }
        }

        if (!tdxTcbFound) {
            return (false, TCBStatus.TCB_UNRECOGNIZED, TCB_LEVEL_ERROR);
        }
    }

    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L62-L97
    function checkTdxModuleTcbStatus(bytes16 teeTcbSvn, TDXModuleIdentity[] memory tdxModuleIdentities)
        internal
        pure
        returns (bool, TCBStatus, uint8, bytes memory, bytes8)
    {
        uint8 tdxModuleIsvSvn = uint8(teeTcbSvn[0]);
        uint8 tdxModuleVersion = uint8(teeTcbSvn[1]);
        bytes memory expectedMrSignerSeam;
        bytes8 expectedSeamAttributes;

        if (tdxModuleVersion == 0) {
            return (true, TCBStatus.OK, tdxModuleVersion, expectedMrSignerSeam, expectedSeamAttributes);
        }

        string memory tdxModuleIdentityId = string(
            abi.encodePacked(bytes("TDX_"), bytes(LibString.toHexStringNoPrefix(abi.encodePacked(tdxModuleVersion))))
        );

        bool tdxModuleIdentityFound;
        TCBStatus moduleStatus;

        for (uint256 i = 0; i < tdxModuleIdentities.length; i++) {
            TDXModuleIdentity memory currId = tdxModuleIdentities[i];
            if (tdxModuleIdentityId.eq(currId.id)) {
                TDXModuleTCBLevelsObj[] memory tdxModuleTcbLevels = currId.tcbLevels;
                for (uint256 j = 0; j < tdxModuleTcbLevels.length; j++) {
                    if (tdxModuleIsvSvn >= uint8(tdxModuleTcbLevels[j].isvsvn)) {
                        tdxModuleIdentityFound = true;
                        moduleStatus = tdxModuleTcbLevels[j].status;
                        expectedMrSignerSeam = currId.mrsigner;
                        expectedSeamAttributes = currId.attributes;
                        break;
                    }
                }
                break;
            }
        }

        if (tdxModuleIdentityFound) {
            return (true, moduleStatus, tdxModuleVersion, expectedMrSignerSeam, expectedSeamAttributes);
        } else {
            return (false, TCBStatus.TCB_UNRECOGNIZED, tdxModuleVersion, expectedMrSignerSeam, expectedSeamAttributes);
        }
    }

    function _isTdxTcbHigherOrEqual(bytes16 teeTcbSvn, uint8[] memory tdxSvns) internal pure returns (bool) {
        if (tdxSvns.length != CPUSVN_LENGTH) {
            return false;
        }

        for (uint256 i = 0; i < CPUSVN_LENGTH; i++) {
            if (uint8(teeTcbSvn[i]) < uint8(tdxSvns[i])) {
                return false;
            }
        }

        return true;
    }
}
