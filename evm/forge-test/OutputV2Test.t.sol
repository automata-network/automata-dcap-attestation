// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "forge-std/Test.sol";
import {OutputV2} from "../contracts/types/OutputV2.sol";
import {OutputV2Codec} from "../contracts/utils/OutputV2Codec.sol";

contract OutputV2Harness {
    function encode(OutputV2 memory out) external pure returns (bytes memory) {
        return OutputV2Codec.encode(out);
    }

    function decode(bytes calldata out) external pure returns (OutputV2 memory) {
        return OutputV2Codec.decode(out);
    }
}

contract OutputV2Test is Test {
    OutputV2Harness codec = new OutputV2Harness();

    function example() internal pure returns (OutputV2 memory out) {
        out.formatMajorVersion = 2;
        out.formatMinorVersion = 1;
        out.quoteVersion = 3;
        out.quoteBodyType = 1;
        out.quoteBodyHash = keccak256(new bytes(384));
        out.advisoryIDs = new string[](0);
    }

    function testAllQuoteBodyCombinations() public view {
        for (uint16 version = 3; version <= 5; ++version) {
            for (uint16 body = 1; body <= version - 2; ++body) {
                OutputV2 memory out = example();
                out.quoteVersion = version;
                out.quoteBodyType = body;
                out.quoteBodyHash = keccak256(new bytes(body == 1 ? 384 : body == 2 ? 584 : 648));
                bytes memory encoded = codec.encode(out);
                assertEq(encoded.length, 317);
                assertEq(uint8(encoded[4]), 6);
                assertEq(uint8(encoded[9]), 0);
                assertEq(codec.encode(codec.decode(encoded)), encoded);
            }
        }
    }

    function testAdvisoryOrderDuplicatesUnicodeAndEmptyString() public view {
        OutputV2 memory out = example();
        out.advisoryIDs = new string[](4);
        out.advisoryIDs[0] = "INTEL-SA-00001";
        out.advisoryIDs[1] = unicode"é证书";
        out.advisoryIDs[2] = "INTEL-SA-00001";
        out.advisoryIDs[3] = "";
        bytes memory encoded = codec.encode(out);
        assertEq(codec.encode(codec.decode(encoded)), encoded);
    }

    function testRejectsMutations() public {
        uint256[8] memory offsets = [uint256(0), 3, 4, 9, 48, 32, 49, 51];
        uint8[8] memory values = [uint8(1), 2, 0, 10, 2, 1, 1, 1];
        for (uint256 i; i < offsets.length; ++i) {
            bytes memory encoded = codec.encode(example());
            encoded[offsets[i]] = bytes1(values[i]);
            vm.expectRevert();
            codec.decode(encoded);
        }
    }

    function testFuzzRejectsTruncation(uint16 length) public {
        bytes memory encoded = codec.encode(example());
        uint256 size = bound(length, 0, encoded.length - 1);
        bytes memory truncated = new bytes(size);
        for (uint256 i; i < size; ++i) {
            truncated[i] = encoded[i];
        }
        vm.expectRevert();
        codec.decode(truncated);
    }

    function testRejectsTrailingBytesAndNoncanonicalPadding() public {
        bytes memory encoded = codec.encode(example());
        vm.expectRevert();
        codec.decode(bytes.concat(encoded, hex"00"));
        OutputV2 memory out = example();
        out.advisoryIDs = new string[](1);
        out.advisoryIDs[0] = "a";
        encoded = codec.encode(out);
        encoded[encoded.length - 1] = 0x01;
        vm.expectRevert();
        codec.decode(encoded);
    }

    function testAllZeroPresentPiidAndRelaunchAreValid() public view {
        OutputV2 memory out = example();
        out.piidPresent = true;
        out.tcbStatus = 9;
        assertEq(codec.encode(codec.decode(codec.encode(out))), codec.encode(out));
    }

    function testOversizeRejected() public {
        OutputV2 memory out = example();
        out.advisoryIDs = new string[](1);
        out.advisoryIDs[0] = string(new bytes(65535));
        vm.expectRevert();
        codec.encode(out);
    }

    function testSharedWireVectors() public view {
        string[3] memory names = ["sgx-empty", "tdx10-advisories", "tdx15-relaunch"];
        for (uint256 i; i < names.length; ++i) {
            bytes memory content =
                bytes(vm.readFile(string.concat(vm.projectRoot(), "/forge-test/assets/v2/", names[i], ".hex")));
            if (content[content.length - 1] == 0x0a) assembly ("memory-safe") { mstore(
                content,
                sub(mload(content), 1)
            ) }
            bytes memory data = vm.parseBytes(string(content));
            OutputV2 memory out = codec.decode(data);
            assertEq(out.timestamp, 0x0102030405060708);
            assertEq(out.ppid, bytes16(0));
            assertEq(codec.encode(out), data);
        }
    }
}
