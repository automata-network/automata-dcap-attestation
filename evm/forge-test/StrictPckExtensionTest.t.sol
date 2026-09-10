// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "forge-std/Test.sol";
import {StrictPckExtension} from "@automata-network/on-chain-pccs/helpers/StrictPckExtension.sol";
import {BytesUtils} from "../contracts/utils/BytesUtils.sol";

contract StrictPckHarness {
    function parse(bytes memory der) external pure returns (StrictPckExtension.Identity memory) {
        return StrictPckExtension.parse(der, 0);
    }
}

contract StrictPckExtensionTest is Test {
    using BytesUtils for bytes;
    StrictPckHarness parser = new StrictPckHarness();
    bytes constant PREFIX = hex"2a864886f84d010d01";

    function tlv(bytes1 tag, bytes memory value) internal pure returns (bytes memory) {
        bytes memory length = value.length < 128
            ? abi.encodePacked(uint8(value.length))
            : value.length < 256
                ? abi.encodePacked(hex"81", uint8(value.length))
                : abi.encodePacked(hex"82", uint16(value.length));
        return bytes.concat(tag, length, value);
    }

    function field(bytes memory prefix, uint8 id, bytes memory value) internal pure returns (bytes memory) {
        return tlv(0x30, bytes.concat(tlv(0x06, bytes.concat(prefix, bytes1(id))), value));
    }

    function fields() internal pure returns (bytes memory) {
        bytes memory nested;
        for (uint8 i = 1; i <= 17; ++i) {
            nested = bytes.concat(nested, field(bytes.concat(PREFIX, hex"02"), i, hex"020100"));
        }
        nested = bytes.concat(nested, field(bytes.concat(PREFIX, hex"02"), 18, tlv(0x04, new bytes(16))));
        return bytes.concat(
            field(PREFIX, 1, tlv(0x04, new bytes(16))),
            field(PREFIX, 2, tlv(0x30, nested)),
            field(PREFIX, 3, hex"04020000"),
            field(PREFIX, 4, hex"0406000000000000"),
            field(PREFIX, 5, hex"0a0100")
        );
    }

    function extension(bytes memory inner) internal pure returns (bytes memory) {
        return tlv(0x30, bytes.concat(tlv(0x06, PREFIX), tlv(0x04, tlv(0x30, inner))));
    }

    function wrap(bytes memory inner) internal pure returns (bytes memory) {
        return tlv(0xa3, tlv(0x30, extension(inner)));
    }

    function testRequiredPpidMayBeZero() public view {
        StrictPckExtension.Identity memory identity = parser.parse(wrap(fields()));
        assertEq(identity.ppid, bytes16(0));
        assertFalse(identity.piidPresent);
        assertEq(identity.cpusvns.length, 16);
    }

    function testPresentPiidMayBeZero() public view {
        StrictPckExtension.Identity memory identity =
            parser.parse(wrap(bytes.concat(fields(), field(PREFIX, 6, tlv(0x04, new bytes(16))))));
        assertTrue(identity.piidPresent);
        assertEq(identity.piid, bytes16(0));
    }

    function testRejectsDuplicateOuterSgxExtension() public {
        bytes memory ext = extension(fields());
        bytes memory der = tlv(0xa3, tlv(0x30, bytes.concat(ext, ext)));
        vm.expectRevert();
        parser.parse(der);
    }

    function testRejectsDuplicateAndUnknownAndMalformedValuesAfterRequiredFields() public {
        bytes memory base = fields();
        bytes[5] memory invalid = [
            field(PREFIX, 1, tlv(0x04, new bytes(16))),
            field(PREFIX, 8, hex"020100"),
            field(PREFIX, 6, tlv(0x04, new bytes(15))),
            field(PREFIX, 6, tlv(0x02, new bytes(16))),
            field(PREFIX, 7, hex"3000")
        ];
        for (uint256 i; i < invalid.length; ++i) {
            bytes memory der = wrap(bytes.concat(base, invalid[i]));
            vm.expectRevert();
            parser.parse(der);
        }
    }

    function testFuzzRejectsTruncatedDer(uint16 length) public {
        bytes memory der = wrap(fields());
        uint256 size = bound(length, 0, der.length - 1);
        bytes memory truncated = new bytes(size);
        for (uint256 i; i < size; ++i) {
            truncated[i] = der[i];
        }
        vm.expectRevert();
        parser.parse(truncated);
    }

    function testRejectsMissingRequiredFields() public {
        bytes memory der = wrap(field(PREFIX, 1, tlv(0x04, new bytes(16))));
        vm.expectRevert();
        parser.parse(der);
    }

    function withTcb(bytes memory first, bytes memory pce) internal pure returns (bytes memory) {
        bytes memory nested;
        for (uint8 i = 1; i <= 17; ++i) {
            nested = bytes.concat(
                nested, field(bytes.concat(PREFIX, hex"02"), i, i == 1 ? first : i == 17 ? pce : bytes(hex"020100"))
            );
        }
        nested = bytes.concat(nested, field(bytes.concat(PREFIX, hex"02"), 18, tlv(0x04, new bytes(16))));
        return bytes.concat(
            field(PREFIX, 1, tlv(0x04, new bytes(16))),
            field(PREFIX, 2, tlv(0x30, nested)),
            field(PREFIX, 3, hex"04020000"),
            field(PREFIX, 4, hex"0406000000000000"),
            field(PREFIX, 5, hex"0a0100")
        );
    }

    function testTcbIntegerDerBounds() public {
        StrictPckExtension.Identity memory parsed = parser.parse(wrap(withTcb(hex"020200ff", hex"020300ffff")));
        assertEq(parsed.cpusvns[0], 255);
        assertEq(parsed.pcesvn, 65535);
        bytes[3] memory invalid = [bytes(hex"0201ff"), hex"02020001", hex"02020100"];
        for (uint256 i; i < invalid.length; ++i) {
            bytes memory der = wrap(withTcb(invalid[i], hex"020100"));
            vm.expectRevert();
            parser.parse(der);
        }
        bytes memory bad = wrap(withTcb(hex"020100", hex"0203010000"));
        vm.expectRevert();
        parser.parse(bad);
    }

    function testMissingPpidWithAllOtherFields() public {
        bytes memory all = fields();
        bytes memory der = wrap(all.substring(32, all.length - 32));
        vm.expectRevert();
        parser.parse(der);
    }

    function testConfigurationBooleans() public {
        bytes memory nested = bytes.concat(
            field(bytes.concat(PREFIX, hex"07"), 1, hex"0101ff"),
            field(bytes.concat(PREFIX, hex"07"), 2, hex"010100"),
            field(bytes.concat(PREFIX, hex"07"), 3, hex"0101ff")
        );
        parser.parse(wrap(bytes.concat(fields(), field(PREFIX, 7, tlv(0x30, nested)))));
        bytes memory invalid = bytes.concat(nested, field(bytes.concat(PREFIX, hex"07"), 3, hex"010100"));
        bytes memory der = wrap(bytes.concat(fields(), field(PREFIX, 7, tlv(0x30, invalid))));
        vm.expectRevert();
        parser.parse(der);
    }
}
