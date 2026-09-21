// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "forge-std/Test.sol";
import {QuotePolicyV2} from "../contracts/utils/QuotePolicyV2.sol";

contract QuotePolicyV2Harness {
    function validate(uint16 bodyType, bytes memory body) external pure {
        QuotePolicyV2.validate(bodyType, body);
    }
}

contract QuotePolicyV2Test is Test {
    QuotePolicyV2Harness policy = new QuotePolicyV2Harness();

    function testSgxDebugOnlyV2() public {
        bytes memory body = new bytes(384);
        policy.validate(1, body);
        body[48] = 0x02;
        vm.expectRevert(bytes("SGX debug mode is enabled"));
        policy.validate(1, body);
    }

    function testTdxAttributesAllBitsMatchRust() public {
        for (uint256 bit; bit < 64; ++bit) {
            bytes memory body = new bytes(584);
            body[123] = 0x10;
            body[120 + bit / 8] |= bytes1(uint8(1 << (bit % 8)));
            if (bit != 28 && bit != 30 && bit != 31 && bit != 63) vm.expectRevert();
            policy.validate(2, body);
        }
        bytes memory missing = new bytes(584);
        vm.expectRevert(bytes("TDX SEPT_VE_DISABLE is not enabled"));
        policy.validate(2, missing);
    }

    function testMigrationMeasurementOnlyV2() public {
        bytes memory body = new bytes(648);
        body[123] = 0x10;
        policy.validate(3, body);
        body[647] = 0x01;
        vm.expectRevert(bytes("TDX migration service TD measurement is not zero"));
        policy.validate(3, body);
    }
}
