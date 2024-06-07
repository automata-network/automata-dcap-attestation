//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    TCBLevelsObj,
    TCBStatus,
    TcbId,
    TDXModule,
    TDXModuleIdentity,
    TDXTCBLevelsObj
} from "@automata-network/on-chain-pccs/helper/FmspcTcbHelper.sol";
import {EnclaveIdTcbStatus} from "@automata-network/on-chain-pccs/helper/EnclaveIdentityHelper.sol";
import {LibString} from "solady/utils/LibString.sol";
import {PCKCertTCB} from "../types/CommonStruct.sol";

abstract contract TCBInfoBase {
    using LibString for string;

    // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/e7604e02331b3377f3766ed3653250e03af72d45/QuoteVerification/QVL/Src/AttestationLibrary/src/CertVerification/X509Constants.h#L64
    uint256 constant CPUSVN_LENGTH = 16;

    function getSGXTcbStatus(PCKCertTCB memory pckTcb, TCBLevelsObj memory current)
        internal
        pure
        returns (bool, TCBStatus status)
    {
        bool pceSvnIsHigherOrGreater;
        bool cpuSvnsAreHigherOrGreater;
        (pceSvnIsHigherOrGreater, cpuSvnsAreHigherOrGreater) = _checkSgxCpuSvns(pckTcb, current);
        status = current.status;
        bool statusFound = pceSvnIsHigherOrGreater && cpuSvnsAreHigherOrGreater;
        return (statusFound, statusFound ? status : TCBStatus.TCB_UNRECOGNIZED);
    }

    function getTDXTcbStatus(bytes16 teeTcbSvn, TCBLevelsObj memory current)
        internal
        pure
        returns (bool, TCBStatus status)
    {
        bool tcbSvnsAreHigherOrEqual = _isTdxTcbHigherOrEqual(teeTcbSvn, current.tdxSvns);
        return (tcbSvnsAreHigherOrEqual, tcbSvnsAreHigherOrEqual ? current.status : TCBStatus.TCB_UNRECOGNIZED);
    }

    function _checkSgxCpuSvns(PCKCertTCB memory pckTcb, TCBLevelsObj memory tcbLevel)
        private
        pure
        returns (bool, bool)
    {
        bool pceSvnIsHigherOrGreater = pckTcb.pcesvn >= tcbLevel.pcesvn;
        bool cpuSvnsAreHigherOrGreater = _isCpuSvnHigherOrGreater(pckTcb.cpusvns, tcbLevel.sgxComponentCpuSvns);
        return (pceSvnIsHigherOrGreater, cpuSvnsAreHigherOrGreater);
    }

    function _isCpuSvnHigherOrGreater(uint8[] memory pckCpuSvns, uint256[] memory tcbCpuSvns)
        private
        pure
        returns (bool)
    {
        if (pckCpuSvns.length != CPUSVN_LENGTH || tcbCpuSvns.length != CPUSVN_LENGTH) {
            return false;
        }
        for (uint256 i = 0; i < CPUSVN_LENGTH; i++) {
            if (uint256(pckCpuSvns[i]) < tcbCpuSvns[i]) {
                return false;
            }
        }
        return true;
    }

    function _isTdxTcbHigherOrEqual(bytes16 teeTcbSvn, uint256[] memory tdxSvns) private pure returns (bool) {
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

    // function _checkTcbLevelsForV4Quotes(
    //     EnclaveIdTcbStatus qeTcbStatus,
    //     PCKCertTCB memory pckTcb,
    //     TcbId tcbType,
    //     bytes16 teeTcbSvn,
    //     TCBLevelsObj[] memory tcbLevels,
    //     TDXModule memory tdxModule,
    //     TDXModuleIdentity[] memory tdxModuleIdentities
    // ) internal pure returns (bool verified, TCBStatus status, bytes memory, bytes8) {
    //     (bool sgxTcbFound, bool tdxTcbFound, TCBLevelsObj memory sgxTcbLevel, TCBLevelsObj memory tdxTcbLevel) =
    //         _matchTcbLevels(tcbType, tcbLevels, pckTcb, teeTcbSvn);

    //     bytes memory expectedMrSignerSeam;
    //     bytes8 expectedSeamAttributes;

    //     if (!sgxTcbFound) {
    //         return (false, TCBStatus.TCB_UNRECOGNIZED, expectedMrSignerSeam, expectedSeamAttributes);
    //     }

    //     if (tcbType == TcbId.TDX) {
    //         if (!tdxTcbFound) {
    //             return (false, TCBStatus.TCB_UNRECOGNIZED, expectedMrSignerSeam, expectedSeamAttributes);
    //         }

    //         // Step 1: Compare teeTcbSvn to get status from TDXModuleIdentities
    //         // skip this step, if tdxModuleVersion == 0
    //         // https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L62-L97
    //         TCBStatus tdxModuleStatus;
    //         uint8 tdxModuleVersion;
    //         (verified, tdxModuleStatus, tdxModuleVersion, expectedMrSignerSeam, expectedSeamAttributes) =
    //             _checkTdxModuleTcbStatus(teeTcbSvn, tdxModuleIdentities);
    //         if (!verified) {
    //             return (verified, tdxModuleStatus, expectedMrSignerSeam, expectedSeamAttributes);
    //         } else if (tdxModuleVersion == 0) {
    //             expectedMrSignerSeam = tdxModule.mrsigner;
    //             expectedSeamAttributes = tdxModule.attributes;
    //         }

    //         // Step 2: Compare teeTcbSvn to get status from TDXComponent from TCBStatus
    //         // Converge status, if step 1 is performed
    //         status = _convergeTcbStatusWithTdxModuleStatus(tdxTcbLevel.status, tdxModuleStatus);
    //     } else {
    //         status = sgxTcbLevel.status;
    //     }

    //     bool tcbIsRevoked =
    //         status == TCBStatus.TCB_REVOKED || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED;
    //     status = _convergeTcbStatusWithQeTcbStatus(qeTcbStatus, status);
    //     return (!tcbIsRevoked, status, expectedMrSignerSeam, expectedSeamAttributes);
    // }

    // function _convergeTcbStatusWithQeTcbStatus(EnclaveIdTcbStatus qeTcbStatus, TCBStatus tcbStatus)
    //     private
    //     pure
    //     returns (TCBStatus convergedStatus)
    // {
    //     // https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L271-L312
    //     if (qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE) {
    //         if (tcbStatus == TCBStatus.OK || tcbStatus == TCBStatus.TCB_SW_HARDENING_NEEDED) {
    //             convergedStatus = TCBStatus.TCB_OUT_OF_DATE;
    //         }
    //         if (
    //             tcbStatus == TCBStatus.TCB_CONFIGURATION_NEEDED
    //                 || tcbStatus == TCBStatus.TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED
    //         ) {
    //             convergedStatus = TCBStatus.TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
    //         }
    //     } else {
    //         convergedStatus = tcbStatus;
    //     }
    // }

    // /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L62-L97
    // function _checkTdxModuleTcbStatus(bytes16 teeTcbSvn, TDXModuleIdentity[] memory tdxModuleIdentities)
    //     private
    //     pure
    //     returns (bool, TCBStatus, uint8, bytes memory, bytes8)
    // {
    //     uint8 tdxModuleIsvSvn = uint8(teeTcbSvn[0]);
    //     uint8 tdxModuleVersion = uint8(teeTcbSvn[1]);
    //     bytes memory expectedMrSignerSeam;
    //     bytes8 expectedSeamAttributes;

    //     if (tdxModuleVersion == 0) {
    //         return (true, TCBStatus.OK, tdxModuleVersion, expectedMrSignerSeam, expectedSeamAttributes);
    //     }

    //     string memory tdxModuleIdentityId = string(
    //         abi.encodePacked(bytes("TDX_"), bytes(LibString.toHexStringNoPrefix(abi.encodePacked(tdxModuleVersion))))
    //     );

    //     bool tdxModuleIdentityFound;
    //     TCBStatus moduleStatus;

    //     for (uint256 i = 0; i < tdxModuleIdentities.length; i++) {
    //         TDXModuleIdentity memory currId = tdxModuleIdentities[i];
    //         if (tdxModuleIdentityId.eq(currId.id)) {
    //             TDXTCBLevelsObj[] memory tdxModuleTcbLevels = currId.tcbLevels;
    //             for (uint256 j = 0; j < tdxModuleTcbLevels.length; j++) {
    //                 if (tdxModuleIsvSvn >= uint8(tdxModuleTcbLevels[j].isvsvn)) {
    //                     tdxModuleIdentityFound = true;
    //                     moduleStatus = tdxModuleTcbLevels[j].status;
    //                     expectedMrSignerSeam = currId.mrsigner;
    //                     expectedSeamAttributes = currId.attributes;
    //                     break;
    //                 }
    //             }
    //             break;
    //         }
    //     }

    //     if (tdxModuleIdentityFound) {
    //         return (true, moduleStatus, tdxModuleVersion, expectedMrSignerSeam, expectedSeamAttributes);
    //     } else {
    //         return (false, TCBStatus.TCB_UNRECOGNIZED, tdxModuleVersion, expectedMrSignerSeam, expectedSeamAttributes);
    //     }
    // }

    // /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp#L129-L181
    // function _matchTcbLevels(
    //     TcbId tcbType,
    //     TCBLevelsObj[] memory tcbLevels,
    //     PCKCertTCB memory pckTcb,
    //     bytes16 teeTcbSvn
    // )
    //     private
    //     pure
    //     returns (bool sgxTcbFound, bool tdxTcbFound, TCBLevelsObj memory sgxTcbLevel, TCBLevelsObj memory tdxTcbLevel)
    // {
    //     bool pceSvnIsHigherOrGreater;
    //     bool cpuSvnsAreHigherOrGreater;
    //     for (uint256 i = 0; i < tcbLevels.length; i++) {
    //         TCBLevelsObj memory current = tcbLevels[i];
    //         if (!sgxTcbFound) {
    //             (pceSvnIsHigherOrGreater, cpuSvnsAreHigherOrGreater) = _checkSgxCpuSvns(pckTcb, current);
    //         }
    //         if (pceSvnIsHigherOrGreater && cpuSvnsAreHigherOrGreater) {
    //             if (!sgxTcbFound) {
    //                 sgxTcbLevel = current;
    //                 sgxTcbFound = true;
    //             }
    //             if (teeTcbSvn != bytes16(0) && tcbType == TcbId.TDX) {
    //                 if (_isTdxTcbHigherOrEqual(teeTcbSvn, current.tdxSvns)) {
    //                     tdxTcbLevel = current;
    //                     tdxTcbFound = true;
    //                 }
    //             }
    //         }
    //         if (sgxTcbFound && (tdxTcbFound || tcbType == TcbId.SGX)) {
    //             break;
    //         }
    //     }
    // }

    // /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L99-L135
    // function _convergeTcbStatusWithTdxModuleStatus(TCBStatus tcbStatus, TCBStatus tdxModuleStatus)
    //     private
    //     pure
    //     returns (TCBStatus convergedStatus)
    // {
    //     if (tdxModuleStatus == TCBStatus.TCB_OUT_OF_DATE) {
    //         if (tcbStatus == TCBStatus.OK || tcbStatus == TCBStatus.TCB_SW_HARDENING_NEEDED) {
    //             convergedStatus = TCBStatus.TCB_OUT_OF_DATE;
    //         }
    //         if (
    //             tcbStatus == TCBStatus.TCB_CONFIGURATION_NEEDED
    //                 || tcbStatus == TCBStatus.TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED
    //         ) {
    //             convergedStatus = TCBStatus.TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
    //         }
    //     } else {
    //         convergedStatus = tcbStatus;
    //     }
    // }
}
