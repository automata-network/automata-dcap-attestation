// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {AutomataDcapAttestationFee} from "../contracts/AutomataDcapAttestationFee.sol";
import {ZkCoProcessorType, ZkCoProcessorConfig} from "../contracts/AttestationEntrypointBase.sol";

/// Operates only on a local fork; no broadcast or replacement of deployed bytecode.
contract DisableLegacyRiscZeroSepoliaForkTest is Test {
    AutomataDcapAttestationFee constant fee = AutomataDcapAttestationFee(0x27188ABA3a26CBb806eF4C67de9b05D7d792EC10);
    address constant owner = 0xDf841B239bE7a6b37366005107069b7410da4Ff9;
    ZkCoProcessorType constant R0 = ZkCoProcessorType.RiscZero;

    function setUp() public {
        string memory rpc = vm.envOr("DCAP_SEPOLIA_READONLY_RPC", string(""));
        if (bytes(rpc).length == 0) { vm.skip(true, "Sepolia archive RPC required"); return; }
        vm.createSelectFork(rpc, 12116262);
        assertEq(block.chainid, 11155111);
        assertEq(address(fee).codehash, 0xd52741a4626a99293e9d38f79ab890ac208953b1e26c2edf958163e0c2f001d0);
        assertEq(fee.owner(), owner);
        vm.txGasPrice(0);
    }

    function unchangedConfig() internal view returns (bytes32) {
        return keccak256(abi.encode(fee.owner(), fee.getBp(), fee.programIdentifier(R0), fee.programIdentifiers(R0),
            fee.zkVerifier(ZkCoProcessorType.Succinct), fee.programIdentifier(ZkCoProcessorType.Succinct),
            fee.programIdentifiers(ZkCoProcessorType.Succinct),
            fee.quoteVerifiers(3), fee.quoteVerifiers(4), fee.quoteVerifiers(5)));
    }

    function testDisablePreservesOtherConfigAndBlocksBothLegacyOverloads() public {
        bytes32 before = unchangedConfig();
        bytes32 id = fee.programIdentifier(R0);
        assertTrue(fee.zkVerifier(R0) != address(0));
        vm.prank(owner);
        fee.setZkConfiguration(R0, ZkCoProcessorConfig(id, address(0)));
        assertEq(fee.zkVerifier(R0), address(0));
        assertEq(unchangedConfig(), before);
        bytes4[6] memory selectors = [bytes4(0xbb001d44), bytes4(0x73c457ba), bytes4(0x242f9d5b),
            bytes4(0x8b38038c), bytes4(0xe71e6620), bytes4(0xffffffff)];
        for (uint256 i; i < selectors.length; ++i) {
            assertEq(fee.zkVerifier(R0, selectors[i]), address(0));
            (bool ok, bytes memory reason) = fee.verifyAndAttestWithZKProof(hex"", R0, abi.encodePacked(selectors[i]));
            assertFalse(ok);
            assertEq(string(reason), "ZK Verifier is not configured");
            (ok, reason) = fee.verifyAndAttestWithZKProof(hex"", R0, abi.encodePacked(selectors[i]), id, 0);
            assertFalse(ok);
            assertEq(string(reason), "ZK Verifier is not configured");
        }
    }

    function testExplicitOverrideSurvivesClearingDefaultAndNeedsSeparateFreeze() public {
        address verifier = fee.zkVerifier(R0);
        bytes32 id = fee.programIdentifier(R0);
        vm.startPrank(owner);
        fee.addVerifyRoute(R0, 0x73c457ba, verifier);
        fee.setZkConfiguration(R0, ZkCoProcessorConfig(id, address(0)));
        assertEq(fee.zkVerifier(R0, 0x73c457ba), verifier);
        fee.freezeVerifyRoute(R0, 0x73c457ba);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSignature("ZK_Route_Frozen(uint8,bytes4)", uint8(1), bytes4(0x73c457ba)));
        fee.zkVerifier(R0, 0x73c457ba);
        (bool ok, bytes memory reason) = fee.verifyAndAttestWithZKProof(hex"", R0, hex"73c457ba");
        assertFalse(ok);
        assertEq(string(reason), "ZK Route has been frozen");
    }

    function testOnlyOwnerCanDisable() public {
        bytes32 id = fee.programIdentifier(R0);
        vm.prank(address(0x1234));
        vm.expectRevert();
        fee.setZkConfiguration(R0, ZkCoProcessorConfig(id, address(0)));
    }
}
