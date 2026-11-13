// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {DeployDcapV2, IReaderStorageV2, IDaoResolverV2} from "../forge-script/DeployDcapV2.s.sol";
import {AutomataDcapAttestationV2} from "../contracts/AutomataDcapAttestationV2.sol";
import {PCCSRouter} from "../contracts/PCCSRouter.sol";
import {V3QuoteVerifier} from "../contracts/verifiers/V3QuoteVerifier.sol";
import {ZkCoProcessorType} from "../contracts/AttestationEntrypointBase.sol";

interface IReplacementSp1Verifier {
    function VERIFIER_HASH() external view returns (bytes32);
}

/// Deployment/configuration acceptance only. No broadcasts, collateral writes or mocked dependencies.
contract DeployDcapV2ReplacementForkTest is Test {
    function testForkReplaceEntrypointWithLiveSp1Configuration() public {
        string memory rpc = vm.envOr("DCAP_REPLACEMENT_RPC", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true, "DCAP_REPLACEMENT_RPC required");
            return;
        }
        vm.createSelectFork(rpc, vm.envUint("DCAP_REPLACEMENT_BLOCK"));
        assertEq(block.chainid, vm.envUint("DCAP_REPLACEMENT_CHAIN"));
        AutomataDcapAttestationV2 previous = AutomataDcapAttestationV2(vm.envAddress("DCAP_REPLACEMENT_SOURCE"));
        PCCSRouter router = PCCSRouter(address(V3QuoteVerifier(address(previous.quoteVerifiers(3))).pccsRouter()));
        address owner = previous.owner();
        bytes32 configSlot = vm.load(address(router), bytes32(uint256(1)));
        address helper = router.pckHelperAddr();
        address sp1 = previous.zkVerifierV2(ZkCoProcessorType.Succinct);
        bytes32 defaultId = previous.programIdentifierV2(ZkCoProcessorType.Succinct);
        bytes32[] memory ids = previous.programIdentifiersV2(ZkCoProcessorType.Succinct);
        IReaderStorageV2 resolver = IReaderStorageV2(IDaoResolverV2(router.pcsDaoAddr()).resolver());
        assertTrue(resolver.isAuthorizedCaller(address(router)));
        DeployDcapV2 script = new DeployDcapV2();
        AutomataDcapAttestationV2 next = script.deployEntrypoint(block.chainid, owner, previous);
        script.authorizeReplacementEntrypoint(block.chainid, router.owner(), previous, next);
        // Hoodi's pinned source uses default fallback, with no explicit route events.
        // For another source, pass the coordinator's full selector/target inventory as ABI bytes.
        bytes memory routeInventory =
            vm.envOr("DCAP_REPLACEMENT_SP1_ROUTES", abi.encode(new bytes4[](0), new address[](0)));
        (bytes4[] memory selectors, address[] memory targets) = abi.decode(routeInventory, (bytes4[], address[]));
        script.migrateSp1Configuration(owner, previous, next, selectors, targets);
        assertEq(next.programIdentifiersV2(ZkCoProcessorType.Succinct), ids);
        assertEq(next.programIdentifierV2(ZkCoProcessorType.Succinct), defaultId);
        assertEq(next.zkVerifierV2(ZkCoProcessorType.Succinct), sp1);
        for (uint256 i; i < ids.length; ++i) {
            (bool registered, bool minimal) = previous.programModeV2(ZkCoProcessorType.Succinct, ids[i]);
            (bool copied, bool copiedMinimal) = next.programModeV2(ZkCoProcessorType.Succinct, ids[i]);
            assertEq(copied, registered);
            assertEq(copiedMinimal, minimal);
        }
        address risc0 = vm.envAddress("DCAP_REPLACEMENT_RISC0_VERIFIER");
        script.configureV2Backend(
            owner,
            next,
            ZkCoProcessorType.RiscZero,
            vm.envBytes32("DCAP_REPLACEMENT_RISC0_STRICT_ID"),
            risc0,
            0xe71e6620
        );
        script.configureMinimalProgram(
            owner, next, ZkCoProcessorType.RiscZero, vm.envBytes32("DCAP_REPLACEMENT_RISC0_MINIMAL_ID")
        );
        ZkCoProcessorType[] memory backends = new ZkCoProcessorType[](2);
        backends[0] = ZkCoProcessorType.RiscZero;
        backends[1] = ZkCoProcessorType.Succinct;
        bytes4[] memory enabled = new bytes4[](2);
        enabled[0] = 0xe71e6620;
        enabled[1] = bytes4(IReplacementSp1Verifier(sp1).VERIFIER_HASH());
        script.enableReplacementZk(block.chainid, owner, previous, next, backends, enabled);
        assertFalse(next.zkV2Paused());
        assertEq(next.zkVerifierV2(ZkCoProcessorType.RiscZero, 0xe71e6620), risc0);
        assertEq(next.zkVerifierV2(ZkCoProcessorType.RiscZero, 0x73c457ba), address(0));
        assertEq(next.getBp(), previous.getBp());
        assertEq(router.pckHelperAddr(), helper);
        assertEq(vm.load(address(router), bytes32(uint256(1))), configSlot);
        assertEq(previous.programIdentifiersV2(ZkCoProcessorType.Succinct), ids);
        assertEq(previous.programIdentifierV2(ZkCoProcessorType.Succinct), defaultId);
        assertFalse(previous.zkV2Paused());
        assertTrue(resolver.isAuthorizedCaller(address(router)));
        assertFalse(resolver.isAuthorizedCaller(address(next)));
        assertEq(uint256(vm.load(address(router), keccak256(abi.encode(address(next), uint256(0))))), 1);
        assertEq(uint256(vm.load(address(router), keccak256(abi.encode(address(previous), uint256(0))))), 1);
    }
}
