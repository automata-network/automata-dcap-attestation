// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import {AutomataDcapAttestationFeeV2} from "../contracts/AutomataDcapAttestationFeeV2.sol";
import "../contracts/verifiers/V3QuoteVerifier.sol";
import "../contracts/verifiers/V4QuoteVerifier.sol";
import "../contracts/verifiers/V5QuoteVerifier.sol";

/// Framing-only tests: deliberately malformed quotes must fail before PCCS/crypto calls.
contract QuoteInputV2Test is Test {
    AutomataDcapAttestationFeeV2 fee;

    function setUp() public {
        fee = new AutomataDcapAttestationFeeV2(address(this));
        fee.setQuoteVerifier(address(new V3QuoteVerifier(address(0), address(0))));
        fee.setQuoteVerifier(address(new V4QuoteVerifier(address(0), address(0))));
        fee.setQuoteVerifier(address(new V5QuoteVerifier(address(0), address(0))));
    }

    function putLE(bytes memory data, uint256 offset, uint256 value, uint256 size) internal pure {
        for (uint256 i; i < size; ++i) data[offset + i] = bytes1(uint8(value >> (i * 8)));
    }

    function sample(uint16 version, uint16 bodyType) internal pure returns (bytes memory raw, uint256 start) {
        uint256 bodyLength = bodyType == 1 ? 384 : bodyType == 2 ? 584 : 648;
        start = 48 + (version == 5 ? 6 : 0) + bodyLength + 4;
        uint256 prefix = version == 3 ? 578 : 584;
        uint256 authLength = prefix + 6 + 32;
        raw = new bytes(start + authLength);
        putLE(raw, 0, version, 2);
        raw[2] = 0x02;
        if (bodyType != 1) raw[4] = 0x81;
        bytes16 vendor = VALID_QE_VENDOR_ID;
        for (uint256 i; i < 16; ++i) raw[12 + i] = vendor[i];
        if (version == 5) {
            putLE(raw, 48, bodyType, 2);
            putLE(raw, 50, bodyLength, 4);
        }
        putLE(raw, start - 4, authLength, 4);
        if (version != 3) {
            putLE(raw, start + 128, 6, 2);
            putLE(raw, start + 130, authLength - 134, 4);
        }
        putLE(raw, start + prefix, 5, 2);
        putLE(raw, start + prefix + 2, 32, 4);
    }

    function assertFailure(bytes memory raw, string memory reason) internal {
        (bool success, bytes memory output) = fee.verifyAndAttestOnChainV2(raw);
        assertFalse(success);
        assertEq(string(output), reason);
    }

    function testAllLayoutsRejectNestedLengthMutationsWithoutPanic() public {
        for (uint16 version = 3; version <= 5; ++version) {
            for (uint16 body = 1; body <= version - 2; ++body) {
                (bytes memory raw, uint256 start) = sample(version, body);
                uint256 prefix = version == 3 ? 578 : 584;
                putLE(raw, start + prefix - 2, 65535, 2);
                assertFailure(raw, ADF);
                putLE(raw, start + prefix - 2, 0, 2);
                putLE(raw, start + prefix + 2, type(uint32).max, 4);
                assertFailure(raw, ADF);
                putLE(raw, start + prefix + 2, 31, 4);
                assertFailure(raw, ADF);
                putLE(raw, start + prefix + 2, 32, 4);
                putLE(raw, start - 4, type(uint32).max, 4);
                assertFailure(raw, ADS);
                putLE(raw, start - 4, raw.length - start - 1, 4);
                assertFailure(raw, ADS);
            }
        }
    }

    function testShortAuthPrefixRejectedAndLegacyBehaviorUnchanged() public {
        for (uint16 version = 4; version <= 5; ++version) {
            for (uint16 body = 1; body <= version - 2; ++body) {
                (bytes memory raw, uint256 start) = sample(version, body);
                // Keep the legacy minimum total size while truncating nested fixed fields.
                assembly ("memory-safe") { mstore(raw, 1020) }
                putLE(raw, start - 4, 1020 - start, 4);
                assertFailure(raw, ADF);
                vm.expectRevert();
                fee.verifyAndAttestOnChain(raw);
            }
        }
    }

    function testFuzzTruncatedQuoteReturnsFailure(uint16 versionSeed, uint16 bodySeed, uint16 length) public {
        uint16 version = uint16(bound(versionSeed, 3, 5));
        uint16 body = uint16(bound(bodySeed, 1, version - 2));
        (bytes memory raw,) = sample(version, body);
        uint256 size = bound(length, 0, raw.length - 1);
        assembly ("memory-safe") { mstore(raw, size) }
        (bool success,) = fee.verifyAndAttestOnChainV2(raw);
        assertFalse(success);
    }
}
