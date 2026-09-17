// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {DeployDcapV2} from "../forge-script/DeployDcapV2.s.sol";
import {AutomataDcapAttestationFee} from "../contracts/AutomataDcapAttestationFee.sol";
import {AutomataDcapAttestationFeeV2} from "../contracts/AutomataDcapAttestationFeeV2.sol";
import {PCCSRouter} from "../contracts/PCCSRouter.sol";
import {V3QuoteVerifier} from "../contracts/verifiers/V3QuoteVerifier.sol";
import {ZkCoProcessorType, ZkCoProcessorConfig} from "../contracts/AttestationEntrypointBase.sol";
import {AutomataDaoStorage} from "@automata-network/on-chain-pccs/automata_pccs/shared/AutomataDaoStorage.sol";

contract IsolatedDaoStub {
    uint32 public constant TCB_EVALUATION_NUMBER = 21;
    address public immutable resolver;

    constructor(address storage_) {
        resolver = storage_;
    }
}

contract DeployDcapV2IsolatedTest is Test {
    DeployDcapV2 script;
    PCCSRouter oldRouter;
    AutomataDcapAttestationFee oldFee;
    AutomataDaoStorage store;
    IsolatedDaoStub dao;
    address owner = address(0x1234);
    uint32[] evals;

    function setUp() public {
        script = new DeployDcapV2();
        store = new AutomataDaoStorage(owner);
        dao = new IsolatedDaoStub(address(store));
        // Real parser is unnecessary for deployment/configuration tests.
        oldRouter = new PCCSRouter(
            address(this), address(dao), address(dao), address(dao), address(dao), address(dao), address(dao)
        );
        oldRouter.setQeIdDaoVersionedAddr(21, address(dao));
        oldRouter.setFmspcTcbDaoVersionedAddr(21, address(dao));
        oldFee = new AutomataDcapAttestationFee(address(this));
        oldFee.setBp(123);
        oldFee.setZkConfiguration(ZkCoProcessorType.Succinct, ZkCoProcessorConfig(bytes32(uint256(99)), address(dao)));
        evals.push(21);
    }

    function deploy() internal returns (DeployDcapV2.Deployment memory d, PCCSRouter router) {
        return script.deployIsolated(block.chainid, owner, oldRouter, oldFee, address(0x100), evals);
    }

    function testIsolatedDeploymentPreservesLegacyAndUsesNewRouter() public {
        (DeployDcapV2.Deployment memory d, PCCSRouter router) = deploy();
        assertTrue(address(router) != address(oldRouter));
        assertTrue(router.pckHelperAddr() != oldRouter.pckHelperAddr());
        assertEq(oldRouter.pckHelperAddr(), address(dao));
        assertEq(oldRouter.owner(), address(this));
        assertEq(oldFee.getBp(), 123);
        assertEq(oldFee.programIdentifier(ZkCoProcessorType.Succinct), bytes32(uint256(99)));
        assertEq(address(oldFee.quoteVerifiers(3)), address(0));
        assertEq(router.qeIdDaoVersionedAddr(21), address(dao));
        assertEq(router.fmspcTcbDaoVersionedAddr(21), address(dao));
        AutomataDcapAttestationFeeV2 fee = AutomataDcapAttestationFeeV2(d.fee);
        assertEq(fee.owner(), owner);
        assertEq(fee.getBp(), 123);
        assertTrue(fee.zkV2Paused());
        assertEq(address(V3QuoteVerifier(d.v3).pccsRouter()), address(router));
        assertEq(address(V3QuoteVerifier(d.v4).pccsRouter()), address(router));
        assertEq(address(V3QuoteVerifier(d.v5).pccsRouter()), address(router));
        assertEq(uint256(vm.load(address(router), keccak256(abi.encode(d.fee, uint256(0))))), 1);
        assertEq(uint256(vm.load(address(router), keccak256(abi.encode(d.v3, uint256(0))))), 1);
        assertEq(uint256(vm.load(address(router), bytes32(uint256(1)))) & 255, 1);
    }

    function testReaderAuthorizationIsAdditiveNotWriterPermission() public {
        (, PCCSRouter router) = deploy();
        vm.prank(owner);
        store.setCallerAuthorization(address(oldRouter), true);
        script.authorizeIsolatedReader(block.chainid, owner, oldRouter, router, address(dao));
        script.authorizeIsolatedReader(block.chainid, owner, oldRouter, router, address(dao));
        assertTrue(store.isAuthorizedCaller(address(oldRouter)));
        assertTrue(store.isAuthorizedCaller(address(router)));
        assertFalse(store.paused());
        vm.prank(address(router));
        vm.expectRevert("FORBIDDEN");
        store.attest(bytes32(uint256(1)), hex"01", bytes32(0));
    }

    function testCanEnableConfiguredTestZkWithoutChangingLegacy() public {
        (DeployDcapV2.Deployment memory d, PCCSRouter router) = deploy();
        AutomataDcapAttestationFeeV2 fee = AutomataDcapAttestationFeeV2(d.fee);
        script.configureV2Backend(owner, fee, ZkCoProcessorType.Succinct, bytes32(uint256(101)), address(dao));
        ZkCoProcessorType[] memory backends = new ZkCoProcessorType[](1);
        backends[0] = ZkCoProcessorType.Succinct;
        script.enableIsolatedZk(block.chainid, owner, oldFee, oldRouter, fee, backends);
        assertFalse(fee.zkV2Paused());
        assertEq(oldFee.programIdentifier(ZkCoProcessorType.Succinct), bytes32(uint256(99)));
        assertEq(oldRouter.pckHelperAddr(), address(dao));
        assertEq(router.pckHelperAddr(), d.helper);
    }

    function testWrongChainAndMissingEvaluationFailBeforeDeployment() public {
        vm.expectRevert("Wrong chain");
        script.deployIsolated(block.chainid + 1, owner, oldRouter, oldFee, address(0x100), evals);
        evals[0] = 22;
        vm.expectRevert("Missing versioned DAO");
        deploy();
    }

    function testRejectSharedRouterReaderAuthorization() public {
        vm.expectRevert("Isolated Router required");
        script.authorizeIsolatedReader(block.chainid, owner, oldRouter, oldRouter, address(dao));
    }

    function testRejectBackendExpansionAndPico() public {
        (DeployDcapV2.Deployment memory d,) = deploy();
        AutomataDcapAttestationFeeV2 fee = AutomataDcapAttestationFeeV2(d.fee);
        script.configureV2Backend(owner, fee, ZkCoProcessorType.RiscZero, bytes32(uint256(101)), address(dao));
        ZkCoProcessorType[] memory backends = new ZkCoProcessorType[](1);
        backends[0] = ZkCoProcessorType.RiscZero;
        vm.expectRevert("Reuse existing backend only");
        script.enableIsolatedZk(block.chainid, owner, oldFee, oldRouter, fee, backends);
        backends[0] = ZkCoProcessorType.Pico;
        vm.expectRevert("Unsupported backend");
        script.enableIsolatedZk(block.chainid, owner, oldFee, oldRouter, fee, backends);
    }
}
