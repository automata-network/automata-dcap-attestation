// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {DeployDcapV2IsolatedTest} from "./DeployDcapV2Isolated.t.sol";
import {DeployDcapV2} from "../forge-script/DeployDcapV2.s.sol";
import {AutomataDcapAttestationV2} from "../contracts/AutomataDcapAttestationV2.sol";
import {PCCSRouter} from "../contracts/PCCSRouter.sol";
import {ZkCoProcessorType} from "../contracts/AttestationEntrypointBase.sol";

contract DeployDcapV2ReplacementTest is DeployDcapV2IsolatedTest {
    function source() internal returns (AutomataDcapAttestationV2 previous, PCCSRouter router) {
        (DeployDcapV2.Deployment memory d, PCCSRouter r) = deploy();
        router = r;
        previous = AutomataDcapAttestationV2(d.attestation);
        vm.startPrank(owner);
        previous.setZkVerifierV2(ZkCoProcessorType.Succinct, address(dao));
        for (uint256 i; i < 6; ++i) {
            previous.addProgramIdentifierV2(ZkCoProcessorType.Succinct, bytes32(i + 10), i % 2 == 1);
        }
        previous.setDefaultProgramIdentifierV2(ZkCoProcessorType.Succinct, bytes32(uint256(12)));
        previous.addVerifyRoute(ZkCoProcessorType.Succinct, 0x12345678, address(dao));
        previous.freezeVerifyRoute(ZkCoProcessorType.Succinct, 0xabcdef01);
        previous.addVerifyRoute(ZkCoProcessorType.RiscZero, 0x73c457ba, address(dao));
        previous.setZkV2Paused(false);
        store.setCallerAuthorization(address(router), true);
        vm.stopPrank();
    }

    function testReplaceOnlyEntrypointPreservesSixSp1ProgramsRoutesAndSharedPermissions() public {
        (AutomataDcapAttestationV2 previous, PCCSRouter router) = source();
        address helper = router.pckHelperAddr();
        bytes32 routerConfig = vm.load(address(router), bytes32(uint256(1)));
        uint64 nonce = vm.getNonce(owner);
        AutomataDcapAttestationV2 next = script.deployEntrypoint(block.chainid, owner, previous);
        assertTrue(address(next) != address(previous));
        // One CREATE plus configuration CALLs: all dependency addresses remain identical.
        assertEq(address(next), vm.computeCreateAddress(owner, nonce));
        assertEq(next.getBp(), previous.getBp());
        assertTrue(next.zkV2Paused());
        for (uint16 v = 3; v <= 5; ++v) {
            assertEq(address(next.quoteVerifiers(v)), address(previous.quoteVerifiers(v)));
        }
        assertEq(vm.load(address(router), keccak256(abi.encode(address(next), uint256(0)))), bytes32(0));
        script.authorizeReplacementEntrypoint(block.chainid, owner, previous, next);
        assertEq(uint256(vm.load(address(router), keccak256(abi.encode(address(next), uint256(0))))), 1);
        assertEq(uint256(vm.load(address(router), keccak256(abi.encode(address(previous), uint256(0))))), 1);
        assertTrue(store.isAuthorizedCaller(address(router)));
        assertFalse(store.isAuthorizedCaller(address(next)));
        bytes4[] memory routes = new bytes4[](2);
        routes[0] = 0x12345678;
        routes[1] = 0xabcdef01;
        address[] memory targets = new address[](2);
        targets[0] = address(dao);
        targets[1] = address(0xdead);
        script.migrateSp1Configuration(owner, previous, next, routes, targets);
        assertEq(
            next.programIdentifiersV2(ZkCoProcessorType.Succinct),
            previous.programIdentifiersV2(ZkCoProcessorType.Succinct)
        );
        assertEq(next.programIdentifierV2(ZkCoProcessorType.Succinct), bytes32(uint256(12)));
        assertEq(next.zkVerifierV2(ZkCoProcessorType.Succinct), address(dao));
        assertEq(next.zkVerifierV2(ZkCoProcessorType.Succinct, routes[0]), address(dao));
        for (uint256 i; i < 6; ++i) {
            (bool registered, bool minimal) = next.programModeV2(ZkCoProcessorType.Succinct, bytes32(i + 10));
            assertTrue(registered);
            assertEq(minimal, i % 2 == 1);
        }
        vm.expectRevert(abi.encodeWithSignature("ZK_Route_Frozen(uint8,bytes4)", uint8(2), routes[1]));
        next.zkVerifierV2(ZkCoProcessorType.Succinct, routes[1]);
        assertEq(next.zkVerifierV2(ZkCoProcessorType.RiscZero, 0x73c457ba), address(0));
        script.configureV2Backend(
            owner, next, ZkCoProcessorType.RiscZero, bytes32(uint256(100)), address(dao), 0xe71e6620
        );
        script.configureMinimalProgram(owner, next, ZkCoProcessorType.RiscZero, bytes32(uint256(101)));
        ZkCoProcessorType[] memory backends = new ZkCoProcessorType[](2);
        backends[0] = ZkCoProcessorType.RiscZero;
        backends[1] = ZkCoProcessorType.Succinct;
        bytes4[] memory enabledSelectors = new bytes4[](2);
        enabledSelectors[0] = 0xe71e6620;
        enabledSelectors[1] = routes[0];
        script.enableReplacementZk(block.chainid, owner, previous, next, backends, enabledSelectors);
        assertFalse(next.zkV2Paused());
        assertFalse(previous.zkV2Paused());
        assertEq(router.pckHelperAddr(), helper);
        assertEq(vm.load(address(router), bytes32(uint256(1))), routerConfig);
        assertEq(previous.programIdentifierV2(ZkCoProcessorType.Succinct), bytes32(uint256(12)));
    }

    function testReplacementGuardsWrongChainSourceOwnerAndRouteDrift() public {
        (AutomataDcapAttestationV2 previous,) = source();
        vm.expectRevert("Wrong chain");
        script.deployEntrypoint(block.chainid + 1, owner, previous);
        AutomataDcapAttestationV2 next = script.deployEntrypoint(block.chainid, owner, previous);
        vm.expectRevert("Router owner/state mismatch");
        script.authorizeReplacementEntrypoint(block.chainid, address(this), previous, next);
        vm.expectRevert("New entrypoint required");
        script.authorizeReplacementEntrypoint(block.chainid, owner, previous, previous);
        bytes4[] memory routes = new bytes4[](1);
        routes[0] = 0x12345678;
        address[] memory targets = new address[](1);
        targets[0] = address(0xdead);
        vm.expectRevert("Source freeze mismatch");
        script.migrateSp1Configuration(owner, previous, next, routes, targets);
        assertEq(next.programIdentifiersV2(ZkCoProcessorType.Succinct).length, 0);
        targets[0] = address(dao);
        routes[0] = 0xabcdef01;
        vm.expectRevert("Source route mismatch");
        script.migrateSp1Configuration(owner, previous, next, routes, targets);
        vm.prank(owner);
        previous.setZkV2Paused(true);
        ZkCoProcessorType[] memory backends = new ZkCoProcessorType[](1);
        backends[0] = ZkCoProcessorType.Succinct;
        vm.expectRevert("Source ZK is paused; review before enabling replacement");
        script.enableReplacementZk(block.chainid, owner, previous, next, backends, routes);
    }
}
