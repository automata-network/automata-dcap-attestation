// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import {BytesUtils} from "./BytesUtils.sol";

/// @dev Matches dcap-rs DcapVerificationPolicy::production(). Only V2 calls this policy.
library QuotePolicyV2 {
    using BytesUtils for bytes;

    function validate(uint16 bodyType, bytes memory body) internal pure {
        if (bodyType == 1) {
            require(body.length == 384, "Invalid SGX body length");
            require(uint8(body[48]) & 0x02 == 0, "SGX debug mode is enabled");
            return;
        }
        require((bodyType == 2 && body.length == 584) || (bodyType == 3 && body.length == 648), "Invalid TDX body");
        if (bodyType == 3) {
            require(
                keccak256(body.substring(600, 48)) == keccak256(new bytes(48)),
                "TDX migration service TD measurement is not zero"
            );
        }
        require(uint8(body[120]) & 0x01 == 0, "TDX debug mode is enabled");
        require(
            uint8(body[120]) & 0xfe == 0 && body[121] == 0 && body[122] == 0 && uint8(body[123]) & 0x2f == 0
                && body[124] == 0 && body[125] == 0 && body[126] == 0 && uint8(body[127]) & 0x7f == 0,
            "reserved TDX attribute bits are set"
        );
        require(uint8(body[123]) & 0x10 != 0, "TDX SEPT_VE_DISABLE is not enabled");
    }
}
