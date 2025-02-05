// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import {EnclaveIdentityHelper, EnclaveId, IdentityObj} from "../../src/helpers/EnclaveIdentityHelper.sol";
import {IdentityConstants} from "./IdentityConstants.t.sol";

contract IdentityHelperTest is IdentityConstants, Test {
    EnclaveIdentityHelper enclaveIdentityLib;

    function setUp() public {
        enclaveIdentityLib = new EnclaveIdentityHelper();
    }

    function testIdentityParser() public {
        IdentityObj memory identity = enclaveIdentityLib.parseIdentityString(string(identityStr));
        assertEq(identity.version, 2);
        assertEq(identity.tcbEvaluationDataNumber, 16);
        assertEq(identity.miscselect, bytes4(0));
        assertEq(identity.miscselectMask, bytes4(0xFFFFFFFF));
        assertEq(identity.attributes, bytes16(0x11000000000000000000000000000000));
        assertEq(identity.attributesMask, bytes16(0xFBFFFFFFFFFFFFFF0000000000000000));
        assertEq(identity.mrsigner, bytes32(0x8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF));
        assertEq(identity.isvprodid, 1);
    }
}
