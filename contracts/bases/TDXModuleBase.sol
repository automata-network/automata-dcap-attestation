//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BytesUtils} from "../utils/BytesUtils.sol";

import {TCBStatus} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";

abstract contract TDXModuleBase {
    using BytesUtils for bytes;

    function checkTdxModule(
        bytes memory mrsignerSeam,
        bytes memory expectedMrsignerSeam,
        bytes8 seamAttributes,
        bytes8 expectedSeamAttributes
    ) internal pure returns (bool) {
        return mrsignerSeam.equals(expectedMrsignerSeam) && seamAttributes == expectedSeamAttributes;
    }

    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L99-L135
    function convergeTcbStatusWithTdxModuleStatus(TCBStatus tcbStatus, TCBStatus tdxModuleStatus)
        internal
        pure
        returns (TCBStatus convergedStatus)
    {
        if (tdxModuleStatus == TCBStatus.TCB_OUT_OF_DATE) {
            if (tcbStatus == TCBStatus.OK || tcbStatus == TCBStatus.TCB_SW_HARDENING_NEEDED) {
                convergedStatus = TCBStatus.TCB_OUT_OF_DATE;
            }
            if (
                tcbStatus == TCBStatus.TCB_CONFIGURATION_NEEDED
                    || tcbStatus == TCBStatus.TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED
            ) {
                convergedStatus = TCBStatus.TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
            }
        } else {
            convergedStatus = tcbStatus;
        }
    }
}
