// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "forge-std/Script.sol";
import {PCKHelper} from "@automata-network/on-chain-pccs/helpers/PCKHelper.sol";
import {AutomataDcapAttestationFee} from "../contracts/AutomataDcapAttestationFee.sol";
import {AutomataDcapAttestationFeeV2} from "../contracts/AutomataDcapAttestationFeeV2.sol";
import {
    AttestationEntrypointBase,
    ZkCoProcessorConfig,
    ZkCoProcessorType
} from "../contracts/AttestationEntrypointBase.sol";
import {PCCSRouter} from "../contracts/PCCSRouter.sol";
import {V3QuoteVerifier} from "../contracts/verifiers/V3QuoteVerifier.sol";
import {V4QuoteVerifier} from "../contracts/verifiers/V4QuoteVerifier.sol";
import {V5QuoteVerifier} from "../contracts/verifiers/V5QuoteVerifier.sol";

interface IReaderStorageV2 {
    function owner() external view returns (address);
    function isAuthorizedCaller(address caller) external view returns (bool);
    function setCallerAuthorization(address caller, bool authorized) external;
}

interface IDaoResolverV2 {
    function resolver() external view returns (address);
}

/// @notice Explicit, single-chain stages. Never rewrites current registry keys or deploys universal verifiers.
/// @dev Run simulations first. --broadcast and the owner's signer are separate operator actions.
contract DeployDcapV2 is Script {
    struct Deployment {
        address helper;
        address fee;
        address v3;
        address v4;
        address v5;
    }

    /// @notice Isolated test deployment: no setter is called on the legacy Fee/Router/DAOs.
    /// @dev The explicit evaluation inventory must be reviewed before broadcast. No registry is
    /// written by simulation: publish-v2.mjs reads the confirmed live deployment separately.
    function deployIsolated(
        uint256 expectedChainId,
        address owner,
        PCCSRouter legacyRouter,
        AutomataDcapAttestationFee legacyFee,
        address p256,
        uint32[] calldata evaluations
    ) external returns (Deployment memory d, PCCSRouter router) {
        require(block.chainid == expectedChainId, "Wrong chain");
        require(owner != address(0), "Invalid owner");
        require(address(legacyRouter).code.length > 0 && address(legacyFee).code.length > 0, "Missing legacy");
        require(p256 == address(0x100) || p256.code.length > 0, "Invalid P256 verifier");
        require(evaluations.length > 0, "Missing evaluation inventory");
        address[5] memory shared = [
            legacyRouter.tcbEvalDaoAddr(),
            legacyRouter.pcsDaoAddr(),
            legacyRouter.pckDaoAddr(),
            legacyRouter.crlHelperAddr(),
            legacyRouter.fmspcTcbHelperAddr()
        ];
        for (uint256 i; i < shared.length; ++i) {
            require(shared[i].code.length > 0, "Missing dependency");
        }
        for (uint256 i; i < evaluations.length; ++i) {
            require(i == 0 || evaluations[i] > evaluations[i - 1], "Unsorted evaluation inventory");
            require(
                legacyRouter.qeIdDaoVersionedAddr(evaluations[i]).code.length > 0
                    && legacyRouter.fmspcTcbDaoVersionedAddr(evaluations[i]).code.length > 0,
                "Missing versioned DAO"
            );
        }

        vm.startBroadcast(owner);
        d.helper = address(new PCKHelper());
        router = new PCCSRouter(owner, shared[0], shared[1], shared[2], d.helper, shared[3], shared[4]);
        d.fee = address(new AutomataDcapAttestationFeeV2(owner));
        d.v3 = address(new V3QuoteVerifier(p256, address(router)));
        d.v4 = address(new V4QuoteVerifier(p256, address(router)));
        d.v5 = address(new V5QuoteVerifier(p256, address(router)));
        AutomataDcapAttestationFeeV2 fee = AutomataDcapAttestationFeeV2(d.fee);
        fee.setBp(legacyFee.getBp());
        fee.setZkV2Paused(true);
        address[3] memory verifiers = [d.v3, d.v4, d.v5];
        for (uint256 i; i < verifiers.length; ++i) {
            fee.setQuoteVerifier(verifiers[i]);
            router.setAuthorized(verifiers[i], true);
        }
        router.setAuthorized(d.fee, true);
        router.enableCallerRestriction();
        for (uint256 i; i < evaluations.length; ++i) {
            router.setQeIdDaoVersionedAddr(evaluations[i], legacyRouter.qeIdDaoVersionedAddr(evaluations[i]));
            router.setFmspcTcbDaoVersionedAddr(evaluations[i], legacyRouter.fmspcTcbDaoVersionedAddr(evaluations[i]));
        }
        vm.stopBroadcast();
        console.log("PCCSRouterV2", address(router));
        console.log("PCKHelperV2", d.helper);
        console.log("AutomataDcapAttestationFeeV2", d.fee);
        console.log("V3QuoteVerifierV2", d.v3);
        console.log("V4QuoteVerifierV2", d.v4);
        console.log("V5QuoteVerifierV2", d.v5);
    }

    /// @notice The only shared-contract write in isolated deployment: additive reader permission.
    /// @dev Run for each distinct resolver of the selected DAOs, with its actual owner signer.
    /// Never grants DAO/writer permission or changes caller-restriction settings.
    function authorizeIsolatedReader(
        uint256 expectedChainId,
        address storageOwner,
        PCCSRouter legacyRouter,
        PCCSRouter router,
        address dao
    ) external {
        require(block.chainid == expectedChainId, "Wrong chain");
        require(address(router) != address(legacyRouter), "Isolated Router required");
        require(router.pckHelperAddr() != legacyRouter.pckHelperAddr(), "Isolated helper required");
        IReaderStorageV2 resolver = IReaderStorageV2(IDaoResolverV2(dao).resolver());
        require(resolver.owner() == storageOwner, "Storage owner mismatch");
        if (!resolver.isAuthorizedCaller(address(router))) {
            vm.startBroadcast(storageOwner);
            resolver.setCallerAuthorization(address(router), true);
            vm.stopBroadcast();
        }
    }

    /// @notice Enable an isolated test instance after its explicit backend inventory is configured.
    /// Production release approval and real-proof tests remain separate gates.
    function enableIsolatedZk(
        uint256 expectedChainId,
        address owner,
        AutomataDcapAttestationFee legacyFee,
        PCCSRouter legacyRouter,
        AutomataDcapAttestationFeeV2 fee,
        ZkCoProcessorType[] calldata backends
    ) external {
        require(block.chainid == expectedChainId, "Wrong chain");
        require(address(fee) != address(legacyFee) && fee.owner() == owner, "Invalid target");
        require(backends.length > 0, "Missing backend inventory");
        PCCSRouter router = PCCSRouter(address(V3QuoteVerifier(address(fee.quoteVerifiers(3))).pccsRouter()));
        require(
            address(router) != address(legacyRouter) && router.owner() == owner
                && router.pckHelperAddr() != legacyRouter.pckHelperAddr(),
            "Isolated Router required"
        );
        for (uint16 version = 3; version <= 5; ++version) {
            require(
                address(V3QuoteVerifier(address(fee.quoteVerifiers(version))).pccsRouter()) == address(router),
                "Inconsistent Router"
            );
        }
        for (uint256 i; i < backends.length; ++i) {
            ZkCoProcessorType backend = backends[i];
            require(
                backend == ZkCoProcessorType.RiscZero || backend == ZkCoProcessorType.Succinct, "Unsupported backend"
            );
            require(fee.programIdentifierV2(backend) != bytes32(0), "Missing V2 program");
            require(
                fee.zkVerifierV2(backend, bytes4(0)).code.length > 0
                    && fee.zkVerifierV2(backend, bytes4(0)) == legacyFee.zkVerifier(backend),
                "Reuse existing backend only"
            );
        }
        vm.startBroadcast(owner);
        fee.setZkV2Paused(false);
        vm.stopBroadcast();
    }

    function deploy(address owner, address router, address p256) external returns (Deployment memory d) {
        require(owner != address(0) && router.code.length > 0, "Invalid owner/router");
        require(p256 == address(0x100) || p256.code.length > 0, "Invalid P256 verifier");
        vm.startBroadcast(owner);
        d.helper = address(new PCKHelper());
        d.fee = address(new AutomataDcapAttestationFeeV2(owner));
        d.v3 = address(new V3QuoteVerifier(p256, router));
        d.v4 = address(new V4QuoteVerifier(p256, router));
        d.v5 = address(new V5QuoteVerifier(p256, router));
        vm.stopBroadcast();
        console.log("PCKHelperV2", d.helper);
        console.log("AutomataDcapAttestationFeeV2", d.fee);
        console.log("V3QuoteVerifierV2", d.v3);
        console.log("V4QuoteVerifierV2", d.v4);
        console.log("V5QuoteVerifierV2", d.v5);
    }

    /// @notice Configures only new contracts and caller authorization. Does not switch the shared helper.
    function configure(address owner, PCCSRouter router, AutomataDcapAttestationFee legacy, Deployment calldata d)
        external
    {
        AutomataDcapAttestationFeeV2 fee = AutomataDcapAttestationFeeV2(d.fee);
        require(fee.owner() == owner && router.owner() == owner, "Owner mismatch");
        require(d.fee != address(legacy), "New Fee deployment required");
        address[3] memory verifiers = [d.v3, d.v4, d.v5];
        vm.startBroadcast(owner);
        fee.setBp(legacy.getBp());
        fee.setZkV2Paused(true); // Unpause only after all real-proof/reproducibility gates pass.
        for (uint256 i; i < 3; ++i) {
            require(V3QuoteVerifier(verifiers[i]).quoteVersion() == i + 3, "Quote version mismatch");
            require(address(V3QuoteVerifier(verifiers[i]).pccsRouter()) == address(router), "Router mismatch");
            fee.setQuoteVerifier(verifiers[i]);
            router.setAuthorized(verifiers[i], true);
        }
        // FeeV2 performs output/journal collateral-hash checks, so it also needs Router access.
        router.setAuthorized(d.fee, true);
        vm.stopBroadcast();
    }

    /// @notice Preserves all registered legacy IDs (including compact ATKJ programs) and its default.
    /// @param proofSelectors Complete legacy route-selector inventory reconstructed from configuration/events.
    function migrateLegacyBackend(
        address owner,
        AutomataDcapAttestationFee legacy,
        AutomataDcapAttestationFeeV2 fee,
        ZkCoProcessorType backend,
        bytes4[] calldata proofSelectors
    ) external {
        require(fee.owner() == owner && address(fee) != address(legacy), "Invalid target");
        bytes32 latest = legacy.programIdentifier(backend);
        bytes32[] memory ids = legacy.programIdentifiers(backend);
        address universal = legacy.zkVerifier(backend);
        require(latest != bytes32(0) && universal.code.length > 0, "Legacy backend not configured");
        vm.startBroadcast(owner);
        fee.setZkConfiguration(backend, ZkCoProcessorConfig(latest, universal));
        for (uint256 i; i < ids.length; ++i) {
            if (fee.programIdentifier(backend) != ids[i]) fee.updateProgramIdentifier(backend, ids[i]);
        }
        if (fee.programIdentifier(backend) != latest) fee.updateProgramIdentifier(backend, latest);
        for (uint256 i; i < proofSelectors.length; ++i) {
            try legacy.zkVerifier(backend, proofSelectors[i]) returns (address verifier) {
                fee.addVerifyRoute(backend, proofSelectors[i], verifier);
            } catch (bytes memory reason) {
                require(
                    reason.length >= 4 && bytes4(reason) == AttestationEntrypointBase.ZK_Route_Frozen.selector,
                    "Cannot read legacy proof route"
                );
                fee.freezeVerifyRoute(backend, proofSelectors[i]);
            }
        }
        vm.stopBroadcast();
    }

    /// @notice Registers an audited native program ID with an EXISTING universal verifier.
    function configureV2Backend(
        address owner,
        AutomataDcapAttestationFeeV2 fee,
        ZkCoProcessorType backend,
        bytes32 id,
        address universal
    ) external {
        require(fee.owner() == owner && fee.zkV2Paused(), "Configure V2 while paused");
        vm.startBroadcast(owner);
        fee.setZkConfigurationV2(backend, ZkCoProcessorConfig(id, universal));
        vm.stopBroadcast();
    }

    /// @notice Switch or rollback only pckHelper, reading the other five components from the live Router.
    function switchHelper(address owner, PCCSRouter router, address expectedCurrent, address replacement) external {
        require(router.owner() == owner && router.pckHelperAddr() == expectedCurrent, "Router state changed");
        require(replacement.code.length > 0, "Replacement helper has no code");
        address tcb = router.tcbEvalDaoAddr();
        address pcs = router.pcsDaoAddr();
        address pck = router.pckDaoAddr();
        address crl = router.crlHelperAddr();
        address fmspc = router.fmspcTcbHelperAddr();
        vm.startBroadcast(owner);
        router.setConfig(tcb, pcs, pck, replacement, crl, fmspc);
        vm.stopBroadcast();
        require(
            router.pckHelperAddr() == replacement && router.tcbEvalDaoAddr() == tcb && router.pcsDaoAddr() == pcs
                && router.pckDaoAddr() == pck && router.crlHelperAddr() == crl && router.fmspcTcbHelperAddr() == fmspc,
            "Router readback failed"
        );
    }
}
