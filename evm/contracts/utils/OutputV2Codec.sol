// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {OutputV2} from "../types/OutputV2.sol";

/// @notice Canonical wire format 2.1. The journal and verified output are identical.
library OutputV2Codec {
    uint256 internal constant HEAD_LENGTH = 317;
    uint256 internal constant MAX_LENGTH = 65535;
    error InvalidOutputV2();

    function encode(OutputV2 memory out) internal pure returns (bytes memory encoded) {
        check(out.formatMajorVersion == 2 && out.formatMinorVersion == 1);
        check(out.piidPresent || out.piid == bytes16(0));
        check(out.tcbStatus <= 9);
        bodyLength(out.quoteVersion, out.quoteBodyType);
        bytes memory advisory = out.advisoryIDs.length == 0 ? bytes("") : abi.encode(out.advisoryIDs);
        check(HEAD_LENGTH + advisory.length <= MAX_LENGTH);
        for (uint256 i; i < out.advisoryIDs.length; ++i) {
            checkUtf8(bytes(out.advisoryIDs[i]));
        }
        return abi.encodePacked(
            uint16(2),
            uint16(1),
            uint8(6),
            out.quoteVersion,
            out.quoteBodyType,
            out.tcbStatus,
            out.fmspc,
            out.ppid,
            out.piid,
            out.piidPresent,
            advisory.length == 0 ? uint16(0) : uint16(HEAD_LENGTH),
            uint16(advisory.length),
            out.timestamp,
            out.collateralHashes,
            out.fullQuoteHash,
            out.quoteBodyHash,
            advisory
        );
    }

    function decode(bytes calldata data) internal pure returns (OutputV2 memory out) {
        check(data.length >= HEAD_LENGTH && data.length <= MAX_LENGTH);
        out.formatMajorVersion = uint16(bytes2(data[0:2]));
        out.formatMinorVersion = uint16(bytes2(data[2:4]));
        check(out.formatMajorVersion == 2 && out.formatMinorVersion == 1 && data[4] == 0x06);
        out.quoteVersion = uint16(bytes2(data[5:7]));
        out.quoteBodyType = uint16(bytes2(data[7:9]));
        out.tcbStatus = uint8(data[9]);
        check(out.tcbStatus <= 9);
        out.fmspc = bytes6(data[10:16]);
        out.ppid = bytes16(data[16:32]);
        out.piid = bytes16(data[32:48]);
        check(uint8(data[48]) <= 1);
        out.piidPresent = data[48] == 0x01;
        check(out.piidPresent || out.piid == bytes16(0));
        bodyLength(out.quoteVersion, out.quoteBodyType);
        uint256 advisoryOffset = uint16(bytes2(data[49:51]));
        uint256 advisoryLength = uint16(bytes2(data[51:53]));
        if (advisoryLength == 0) {
            check(advisoryOffset == 0 && data.length == HEAD_LENGTH);
            out.advisoryIDs = new string[](0);
        } else {
            check(advisoryOffset == HEAD_LENGTH && advisoryOffset + advisoryLength == data.length);
            bytes calldata advisory = data[advisoryOffset:];
            out.advisoryIDs = abi.decode(advisory, (string[]));
            check(out.advisoryIDs.length > 0 && keccak256(abi.encode(out.advisoryIDs)) == keccak256(advisory));
            for (uint256 i; i < out.advisoryIDs.length; ++i) {
                checkUtf8(bytes(out.advisoryIDs[i]));
            }
        }
        out.timestamp = uint64(bytes8(data[53:61]));
        for (uint256 i; i < 6; ++i) {
            out.collateralHashes[i] = bytes32(data[61 + i * 32:93 + i * 32]);
        }
        out.fullQuoteHash = bytes32(data[253:285]);
        out.quoteBodyHash = bytes32(data[285:317]);
    }

    function bodyLength(uint16 quoteVersion, uint16 bodyType) internal pure returns (uint256) {
        check(quoteVersion >= 3 && quoteVersion <= 5);
        check(bodyType >= 1 && bodyType <= 3);
        check(quoteVersion != 3 || bodyType == 1);
        check(quoteVersion != 4 || bodyType != 3);
        return bodyType == 1 ? 384 : bodyType == 2 ? 584 : 648;
    }

    function checkUtf8(bytes memory value) private pure {
        uint256 i;
        while (i < value.length) {
            uint8 c = uint8(value[i++]);
            if (c < 0x80) continue;
            uint256 remaining = c >= 0xc2 && c <= 0xdf ? 1 : c >= 0xe0 && c <= 0xef ? 2 : c >= 0xf0 && c <= 0xf4 ? 3 : 0;
            check(remaining != 0 && remaining <= value.length - i);
            uint8 first = uint8(value[i]);
            check((c != 0xe0 || first >= 0xa0) && (c != 0xed || first < 0xa0));
            check((c != 0xf0 || first >= 0x90) && (c != 0xf4 || first < 0x90));
            for (uint256 j; j < remaining; ++j) {
                check(uint8(value[i++]) & 0xc0 == 0x80);
            }
        }
    }

    function check(bool condition) private pure {
        if (!condition) revert InvalidOutputV2();
    }
}
