// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test, console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {JSONParserLib} from "solady/utils/JSONParserLib.sol";
import {LibString} from "solady/utils/LibString.sol";
import {AutomataDcapAttestationFee} from "../contracts/AutomataDcapAttestationFee.sol";
import {AutomataDcapAttestationFeeV2} from "../contracts/AutomataDcapAttestationFeeV2.sol";
import {ZkCoProcessorType, ZkCoProcessorConfig} from "../contracts/AttestationEntrypointBase.sol";
import {PCCSRouter} from "../contracts/PCCSRouter.sol";
import {V3QuoteVerifier} from "../contracts/verifiers/V3QuoteVerifier.sol";
import {V4QuoteVerifier} from "../contracts/verifiers/V4QuoteVerifier.sol";
import {V5QuoteVerifier} from "../contracts/verifiers/V5QuoteVerifier.sol";
import {OutputV2} from "../contracts/types/OutputV2.sol";
import {OutputV2Codec} from "../contracts/utils/OutputV2Codec.sol";
import {DeployDcapV2} from "../forge-script/DeployDcapV2.s.sol";
import {PCKHelper} from "@automata-network/on-chain-pccs/helpers/PCKHelper.sol";
import {CA, PcsDao} from "@automata-network/on-chain-pccs/bases/PcsDao.sol";
import {FmspcTcbDao} from "@automata-network/on-chain-pccs/bases/FmspcTcbDao.sol";
import {FmspcTcbDaoV2} from "@automata-network/on-chain-pccs/bases/FmspcTcbDaoV2.sol";
import {EnclaveIdentityDao} from "@automata-network/on-chain-pccs/bases/EnclaveIdentityDao.sol";
import {TcbInfoJsonObj} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";
import {EnclaveIdentityJsonObj} from "@automata-network/on-chain-pccs/helpers/EnclaveIdentityHelper.sol";

interface IForkRoles {
    function owner() external view returns (address);
    function ATTESTER_ROLE() external view returns (uint256);
    function grantRoles(address caller, uint256 roles) external payable;
}

interface IForkEvm {
    function setEvmVersion(string calldata version) external;
}

interface IForkSp1Gateway {
    function routes(bytes4 selector) external view returns (address verifier, bool frozen);
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}

interface IForkRiscZeroRouter {
    function verifiers(bytes4 selector) external view returns (address);
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}

/// No broadcast, fake verifier, vm.mockCall, DAO replacement, or synthetic signatures.
/// Deliberately separate missing-proof skips from passing raw/deployment checks.
contract DcapV2ForkTest is Test {
    using JSONParserLib for JSONParserLib.Item;
    using LibString for string;
    PCCSRouter internal router;
    AutomataDcapAttestationFee internal legacy;
    AutomataDcapAttestationFeeV2 internal fee;
    address internal owner;
    address internal helper;
    address[3] internal verifiers;
    address[6] internal original;
    uint256 internal chainTimestamp;
    bytes32 internal constant V2_EVENT = keccak256("AttestationSubmittedV2(bool,uint8,uint16,uint16,bytes)");

    receive() external payable {}

    function setUp() public {
        string memory rpc = vm.envOr("DCAP_FORK_RPC", string(""));
        if (bytes(rpc).length == 0) { vm.skip(true, "DCAP_FORK_RPC required"); return; }
        vm.createSelectFork(rpc, vm.envUint("DCAP_FORK_BLOCK"));
        assertEq(block.chainid, vm.envUint("DCAP_FORK_CHAIN"), "wrong chain");
        string memory executionVersion = vm.envOr("DCAP_FORK_EVM", string(""));
        if (bytes(executionVersion).length != 0) {
            IForkEvm(address(vm)).setEvmVersion(executionVersion);
        }
        chainTimestamp = block.timestamp;
        string memory registry = vm.readFile(string.concat(
            "../rust-crates/libraries/network-registry/deployment/current/", vm.toString(block.chainid), "/dcap.json"));
        router = PCCSRouter(vm.parseJsonAddress(registry, ".PCCSRouter"));
        legacy = AutomataDcapAttestationFee(vm.parseJsonAddress(registry, ".AutomataDcapAttestationFee"));
        require(address(router).code.length != 0 && address(legacy).code.length != 0, "missing deployed contracts");
        owner = router.owner();
        original = _config();
        address p256 = PcsDao(original[1]).P256_VERIFIER();
        // Native precompiles have no bytecode. Require an explicit execution
        // hardfork instead of replacing them with a mock or software verifier.
        require(p256.code.length != 0 || (p256 == address(0x100) && bytes(executionVersion).length != 0),
            "native P256 precompile requires an explicit fork configuration");
        vm.deal(address(this), 20 ether);
        vm.txGasPrice(1 gwei);
        vm.startPrank(owner);
        uint256 beforeGas = gasleft();
        helper = address(new PCKHelper());
        console2.log("deployment PCKHelper gas", beforeGas - gasleft());
        beforeGas = gasleft();
        fee = new AutomataDcapAttestationFeeV2(owner);
        console2.log("deployment FeeV2 gas", beforeGas - gasleft());
        beforeGas = gasleft();
        verifiers[0] = address(new V3QuoteVerifier(p256, address(router)));
        console2.log("deployment V3 gas", beforeGas - gasleft());
        beforeGas = gasleft();
        verifiers[1] = address(new V4QuoteVerifier(p256, address(router)));
        console2.log("deployment V4 gas", beforeGas - gasleft());
        beforeGas = gasleft();
        verifiers[2] = address(new V5QuoteVerifier(p256, address(router)));
        console2.log("deployment V5 gas", beforeGas - gasleft());
        fee.setBp(legacy.getBp());
        fee.setZkV2Paused(true);
        for (uint256 i; i < 3; ++i) {
            fee.setQuoteVerifier(verifiers[i]);
            router.setAuthorized(verifiers[i], true);
        }
        router.setAuthorized(address(fee), true);
        for (uint8 kind = 1; kind <= 2; ++kind) _copyDefaults(kind);
        router.setConfig(original[0], original[1], original[2], helper, original[4], original[5]);
        vm.stopPrank();
    }

    function _config() internal view returns (address[6] memory) {
        return [router.tcbEvalDaoAddr(), router.pcsDaoAddr(), router.pckDaoAddr(),
            router.pckHelperAddr(), router.crlHelperAddr(), router.fmspcTcbHelperAddr()];
    }

    function _copyDefaults(uint8 kind) internal {
        ZkCoProcessorType backend = ZkCoProcessorType(kind);
        address universal = legacy.zkVerifier(backend);
        bytes32 latest = legacy.programIdentifier(backend);
        bytes32[] memory ids = legacy.programIdentifiers(backend);
        if (universal == address(0) && latest == bytes32(0) && ids.length == 0) return;
        require(universal.code.length != 0 && latest != bytes32(0), "incomplete legacy default configuration");
        fee.setZkConfiguration(backend, ZkCoProcessorConfig(latest, universal));
        for (uint256 i; i < ids.length; ++i) {
            if (fee.programIdentifier(backend) != ids[i]) fee.updateProgramIdentifier(backend, ids[i]);
        }
        if (fee.programIdentifier(backend) != latest) fee.updateProgramIdentifier(backend, latest);
        bytes32 id = kind == 1
            ? bytes32(0x9d4a47be495ab06a6a84b24d856a13a68312d8fdea487bcb8aa6931a322f9b9b)
            : bytes32(0x000544ec0a86e3860bac6c329267c270beed1f7be600519128022a02f4b9f170);
        fee.setZkConfigurationV2(backend, ZkCoProcessorConfig(id, universal));
        // Full historical route inventory is a separate acceptance item, not inferred here.
    }

    function testForkDeploymentConfigurationAndRollback() public {
        address[6] memory current = _config();
        for (uint256 i; i < 6; ++i) assertEq(current[i], i == 3 ? helper : original[i]);
        assertEq(fee.getBp(), legacy.getBp());
        assertTrue(fee.zkV2Paused());
        for (uint8 kind = 1; kind <= 2; ++kind) {
            ZkCoProcessorType backend = ZkCoProcessorType(kind);
            assertEq(fee.programIdentifier(backend), legacy.programIdentifier(backend));
            bytes32[] memory ids = legacy.programIdentifiers(backend);
            bytes32[] memory migrated = fee.programIdentifiers(backend);
            assertEq(ids.length, migrated.length);
            for (uint256 i; i < ids.length; ++i) {
                bool found; for (uint256 j; j < migrated.length; ++j) if (ids[i] == migrated[j]) found = true;
                assertTrue(found, "missing legacy ID");
            }
        }
        vm.expectRevert(); fee.setZkV2Paused(false);
        vm.startPrank(owner);
        fee.setZkV2Paused(false);
        fee.setZkV2Paused(true);
        router.setConfig(original[0], original[1], original[2], original[3], original[4], original[5]);
        vm.stopPrank();
        current = _config();
        for (uint256 i; i < 6; ++i) assertEq(current[i], original[i]);
    }

    /// Run the operator's actual staged script in simulation, not just the
    /// equivalent setup above. No --broadcast or production signer is used.
    function testForkDeploymentScriptStagesAndGuards() public {
        DeployDcapV2 script = new DeployDcapV2();
        DeployDcapV2.Deployment memory d = script.deploy(owner, address(router), PcsDao(original[1]).P256_VERIFIER());
        AutomataDcapAttestationFeeV2 staged = AutomataDcapAttestationFeeV2(d.fee);
        address[6] memory beforeConfig = _config();
        script.configure(owner, router, legacy, d);
        assertTrue(staged.zkV2Paused());
        assertEq(staged.getBp(), legacy.getBp());
        assertEq(keccak256(abi.encode(_config())), keccak256(abi.encode(beforeConfig)), "configure switched helper early");
        for (uint8 kind = 1; kind <= 2; ++kind) {
            ZkCoProcessorType backend = ZkCoProcessorType(kind);
            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = kind == 1 ? bytes4(0x73c457ba) : bytes4(0xa4594c59);
            script.migrateLegacyBackend(owner, legacy, staged, backend, selectors);
            assertEq(staged.programIdentifier(backend), legacy.programIdentifier(backend));
            bytes32[] memory ids = legacy.programIdentifiers(backend);
            bytes32[] memory migrated = staged.programIdentifiers(backend);
            assertEq(ids.length, migrated.length);
            for (uint256 i; i < ids.length; ++i) {
                bool found;
                for (uint256 j; j < migrated.length; ++j) if (ids[i] == migrated[j]) found = true;
                assertTrue(found, "script dropped a legacy program");
            }
            address universal = legacy.zkVerifier(backend);
            assertEq(staged.zkVerifier(backend, selectors[0]), legacy.zkVerifier(backend, selectors[0]));
            script.configureV2Backend(owner, staged, backend, fee.programIdentifierV2(backend), universal);
            assertEq(staged.programIdentifierV2(backend), fee.programIdentifierV2(backend));
            assertEq(staged.programIdentifier(backend), legacy.programIdentifier(backend), "V2 changed legacy default");
        }
        vm.expectRevert("Router state changed");
        script.switchHelper(owner, router, original[3], d.helper);
        vm.expectRevert("Replacement helper has no code");
        script.switchHelper(owner, router, helper, address(0xbeef));
        script.switchHelper(owner, router, helper, d.helper);
        address[6] memory changed = _config();
        for (uint256 i; i < 6; ++i) assertEq(changed[i], i == 3 ? d.helper : beforeConfig[i]);
        vm.expectRevert("Router state changed");
        script.switchHelper(owner, router, helper, original[3]);
        script.switchHelper(owner, router, d.helper, helper);
        assertEq(keccak256(abi.encode(_config())), keccak256(abi.encode(beforeConfig)), "script rollback altered dependencies");
        vm.prank(owner);
        staged.setZkV2Paused(false);
        address risc0Universal = legacy.zkVerifier(ZkCoProcessorType.RiscZero);
        vm.expectRevert("Configure V2 while paused");
        script.configureV2Backend(owner, staged, ZkCoProcessorType.RiscZero, bytes32(uint256(1)), risc0Universal);
    }

    /// Validate observed historical guards before any proof decoding. These are
    /// rejection tests, not claims to possess valid old-format proofs.
    function testForkRiscZeroHistoricalRouteGuards() public {
        if (block.chainid != 11155111) { vm.skip(true, "historical route catalog is Sepolia-specific"); return; }
        IForkRiscZeroRouter universal = IForkRiscZeroRouter(legacy.zkVerifier(ZkCoProcessorType.RiscZero));
        assertEq(fee.zkVerifier(ZkCoProcessorType.RiscZero), address(universal));
        assertEq(fee.zkVerifierV2(ZkCoProcessorType.RiscZero, 0x73c457ba), address(universal));
        bytes4[2] memory removed = [bytes4(0x50bd1769), bytes4(0xc101b42b)];
        for (uint256 i; i < removed.length; ++i) {
            assertEq(universal.verifiers(removed[i]), address(1));
            vm.expectRevert(abi.encodeWithSignature("SelectorRemoved(bytes4)", removed[i]));
            universal.verify(abi.encodePacked(removed[i]), bytes32(0), bytes32(0));
        }
        bytes4[7] memory stopped = [bytes4(0x9f39696c), bytes4(0xbfca9ccb), bytes4(0xf443ad7b),
            bytes4(0xf2e6e6dc), bytes4(0x80479d24), bytes4(0x0f63ffd5), bytes4(0xf536085a)];
        for (uint256 i; i < stopped.length; ++i) {
            assertGt(uint160(universal.verifiers(stopped[i])), 1);
            vm.expectRevert(bytes4(keccak256("EnforcedPause()")));
            universal.verify(abi.encodePacked(stopped[i]), bytes32(0), bytes32(0));
        }
    }

    function _fixture(string memory name) internal view returns (string memory) {
        return vm.readFile(string.concat("forge-test/assets/v2/fixtures/", name, ".json"));
    }
    function decode(bytes calldata journal) external pure returns (OutputV2 memory) { return OutputV2Codec.decode(journal); }
    function _signed(string memory json, string memory key) internal pure returns (string memory) {
        JSONParserLib.Item[] memory children = JSONParserLib.parse(json).children();
        for (uint256 i; i < children.length; ++i) if (JSONParserLib.decodeString(children[i].key()).eq(key)) return children[i].value();
        revert("missing signed object");
    }
    function _cert(PcsDao pcs, CA ca, bytes memory cert) internal {
        vm.prank(address(0)); (bytes memory existing,) = pcs.getCertificateById(ca);
        if (keccak256(existing) != keccak256(cert)) pcs.upsertPcsCertificates(ca, cert);
    }
    function _upsert(string memory fixture) internal returns (uint32 eval) {
        eval = uint32(vm.parseJsonUint(fixture, ".tcbEvaluationDataNumber"));
        OutputV2 memory expected = this.decode(vm.parseJsonBytes(fixture, ".expectedJournal"));
        PcsDao pcs = PcsDao(router.pcsDaoAddr());
        _cert(pcs, CA.ROOT, vm.parseJsonBytes(fixture, ".rootCaCertificate"));
        _cert(pcs, CA.PLATFORM, vm.parseJsonBytes(fixture, ".platformCaCertificate"));
        _cert(pcs, CA.SIGNING, vm.parseJsonBytes(fixture, ".tcbSigningCertificate"));
        vm.prank(address(0)); (,bytes memory crl) = pcs.getCertificateById(CA.ROOT);
        bytes memory wanted = vm.parseJsonBytes(fixture, ".rootCaCrl");
        if (keccak256(crl) != keccak256(wanted)) pcs.upsertRootCACrl(wanted);
        vm.prank(address(0)); (,crl) = pcs.getCertificateById(CA.PLATFORM);
        wanted = vm.parseJsonBytes(fixture, ".pckCrl");
        if (keccak256(crl) != keccak256(wanted)) pcs.upsertPckCrl(CA.PLATFORM, wanted);
        address fmspcAddr = router.fmspcTcbDaoVersionedAddr(eval);
        address qeAddr = router.qeIdDaoVersionedAddr(eval);
        require(fmspcAddr.code.length != 0 && qeAddr.code.length != 0, "missing existing evaluation DAOs");
        FmspcTcbDao fmspc = FmspcTcbDao(fmspcAddr);
        EnclaveIdentityDao qe = EnclaveIdentityDao(qeAddr);
        uint8 tcbType = expected.quoteBodyType == 1 ? 0 : 1;
        uint256 qeType = expected.quoteBodyType == 1 ? 0 : 2;
        bytes32 fmspcKey = fmspc.FMSPC_TCB_KEY(tcbType, expected.fmspc, 3);
        (uint64 fmspcIssued, uint64 fmspcExpires) = fmspc.getCollateralValidity(fmspcKey);
        if (fmspc.getTcbInfoContentHash(fmspcKey) != expected.collateralHashes[0]
            || fmspcIssued == 0 || block.timestamp < fmspcIssued || block.timestamp > fmspcExpires) {
            uint256 role = IForkRoles(fmspcAddr).ATTESTER_ROLE();
            vm.prank(IForkRoles(fmspcAddr).owner());
            IForkRoles(fmspcAddr).grantRoles(address(this), role);
            string memory tcb = vm.parseJsonString(fixture, ".tcbInfoJson");
            (bool asyncDao, bytes memory protocol) = fmspcAddr.staticcall(abi.encodeWithSignature("asyncUpsertProtocolVersion()"));
            if (asyncDao && protocol.length == 32) {
                assertEq(abi.decode(protocol, (uint8)), 2, "unsupported async upsert protocol");
                _asyncTcb(FmspcTcbDaoV2(fmspcAddr), tcb, expected);
            } else {
                fmspc.upsertFmspcTcb(TcbInfoJsonObj(_signed(tcb, "tcbInfo"), vm.parseJsonBytes(tcb, ".signature")));
            }
        }
        bytes32 qeKey = qe.ENCLAVE_ID_KEY(qeType, 4);
        (uint64 qeIssued, uint64 qeExpires) = qe.getCollateralValidity(qeKey);
        // Body hashes can stay identical across signed collateral renewals.
        // Matching a content hash is not evidence of a currently valid cache.
        if (qe.getIdentityContentHash(qeKey) != expected.collateralHashes[1]
            || qeIssued == 0 || block.timestamp < qeIssued || block.timestamp > qeExpires) {
            uint256 role = IForkRoles(qeAddr).ATTESTER_ROLE();
            vm.prank(IForkRoles(qeAddr).owner());
            IForkRoles(qeAddr).grantRoles(address(this), role);
            string memory identity = vm.parseJsonString(fixture, ".qeIdentityJson");
            qe.upsertEnclaveIdentity(qeType, 4, EnclaveIdentityJsonObj(_signed(identity, "enclaveIdentity"), vm.parseJsonBytes(identity, ".signature")));
        }
    }

    function _asyncTcb(FmspcTcbDaoV2 dao, string memory tcb, OutputV2 memory expected) internal {
        string memory raw = _signed(tcb, "tcbInfo");
        string memory directory = vm.envOr("DCAP_FORK_ASYNC_DIR", string(""));
        string memory file = bytes(directory).length == 0
            ? vm.envString("DCAP_FORK_ASYNC_PAYLOAD")
            : string.concat(directory, "/", vm.parseJsonString(raw, ".fmspc"), "-",
                expected.quoteBodyType == 1 ? "0" : "1", ".json");
        string memory plan = vm.readFile(file);
        assertEq(vm.parseJsonString(plan, ".raw"), raw, "async plan belongs to different signed JSON");
        bytes32 refId = keccak256(abi.encode(address(this), address(dao), raw));
        uint256 beforeGas = gasleft();
        dao.startAsyncUpsert(refId, vm.parseJsonBytes(tcb, ".signature"), uint32(bytes(raw).length));
        console2.log("FMSPC async start gas", beforeGas - gasleft());
        beforeGas = gasleft();
        dao.uploadBasicInfo(refId, vm.parseJsonBytes(plan, ".basicPayload"), vm.parseJsonBytes(plan, ".topLevelOrder"));
        console2.log("FMSPC async basic gas", beforeGas - gasleft());
        for (uint256 group; group < 2; ++group) {
            string memory groupKey = group == 0 ? "levels" : "identities";
            uint256 count = JSONParserLib.parse(plan).at(string.concat('"', groupKey, '"')).children().length;
            if (group == 0) assertGt(count, 0, "missing async TCB batches");
            for (uint256 i; i < count; ++i) {
                string memory prefix = string.concat(".", groupKey, "[", vm.toString(i), "]");
                uint256 start = vm.parseJsonUint(plan, string.concat(prefix, ".start"));
                uint256 items = vm.parseJsonUint(plan, string.concat(prefix, ".count"));
                bytes memory payload = vm.parseJsonBytes(plan, string.concat(prefix, ".payload"));
                beforeGas = gasleft();
                if (group == 0) dao.uploadTcbLevelsBatch(refId, start, items, payload);
                else dao.uploadTdxModuleIdentitiesBatch(refId, start, items, payload);
                console2.log("FMSPC async batch gas", beforeGas - gasleft());
            }
        }
        bytes32 key = dao.FMSPC_TCB_KEY(expected.quoteBodyType == 1 ? 0 : 1, expected.fmspc, 3);
        bytes32 previous = dao.resolver().collateralPointer(key);
        beforeGas = gasleft();
        dao.finalizeAsyncUpsert(previous, refId);
        console2.log("FMSPC async finalize gas", beforeGas - gasleft());
        assertEq(dao.getTcbInfoContentHash(key), expected.collateralHashes[0], "async content hash mismatch");
    }

    function _raw(string memory name) internal {
        string memory fixture = _fixture(name);
        uint256 beforeGas = gasleft();
        uint32 eval = _upsert(fixture);
        console2.log("collateral preparation gas (cached entries skipped)", beforeGas - gasleft());
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        vm.recordLogs();
        beforeGas = gasleft();
        (bool success, bytes memory journal) = fee.verifyAndAttestOnChainV2{value: 1 ether}(quote, eval);
        console2.log("raw verification internal-call gas", beforeGas - gasleft());
        assertTrue(success, string(journal));
        OutputV2 memory expected = this.decode(vm.parseJsonBytes(fixture, ".expectedJournal"));
        expected.timestamp = uint64(chainTimestamp);
        assertEq(journal, OutputV2Codec.encode(expected), "fork-time output mismatch");
        _assertSuccessEvent(vm.getRecordedLogs(), ZkCoProcessorType.None, journal);
        _rejectRaw(bytes.concat(quote, hex"00"), eval);
        quote[80] ^= 0x01;
        _rejectRaw(quote, eval);
    }
    function testForkRawSgxV3() public { _raw("ata-sgx-v3"); }
    function testForkRawTdxV4() public { _raw("ata-tdx-v4"); }
    function testForkRawTdxV5() public { _raw("v5"); }

    function testForkRawSignedCollateralExpiryRejected() public {
        string[3] memory names = [string("ata-sgx-v3"), string("ata-tdx-v4"), string("v5")];
        for (uint256 i; i < names.length; ++i) {
            uint256 snapshot = vm.snapshotState();
            string memory fixture = _fixture(names[i]);
            uint32 eval = _upsert(fixture);
            bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
            (bool success,) = fee.verifyAndAttestOnChainV2{value: 1 ether}(quote, eval);
            assertTrue(success, "pre-expiry control failed");
            OutputV2 memory expected = this.decode(vm.parseJsonBytes(fixture, ".expectedJournal"));
            FmspcTcbDao tcb = FmspcTcbDao(router.fmspcTcbDaoVersionedAddr(eval));
            EnclaveIdentityDao qe = EnclaveIdentityDao(router.qeIdDaoVersionedAddr(eval));
            (, uint64 tcbExpiry) = tcb.getCollateralValidity(
                tcb.FMSPC_TCB_KEY(expected.quoteBodyType == 1 ? 0 : 1, expected.fmspc, 3));
            (, uint64 qeExpiry) = qe.getCollateralValidity(qe.ENCLAVE_ID_KEY(expected.quoteBodyType == 1 ? 0 : 2, 4));
            uint256 expiry = tcbExpiry > qeExpiry ? tcbExpiry : qeExpiry;
            assertGt(expiry, chainTimestamp, "expected currently valid signed collateral");
            // Advance only to test rejection. No unsigned collateral, changed
            // signatures or clock rewind is used to manufacture acceptance.
            vm.warp(expiry + 1);
            _rejectRaw(quote, eval);
            assertTrue(vm.revertToState(snapshot));
        }
    }

    function testForkOriginalPaddedTdxRejected() public {
        string memory fixture = _fixture("ata-tdx-v4");
        uint32 eval = _upsert(fixture);
        (bool success,) = fee.verifyAndAttestOnChainV2{value: 1 ether}(vm.parseJsonBytes(fixture, ".quote"), eval);
        assertTrue(success, "unpadded baseline failed");
        bytes memory padded = vm.parseBytes(vm.readFile("forge-test/assets/v2/quotes/ata-tdx-v4.hex"));
        assertEq(padded.length, 8000);
        _rejectRaw(padded, eval);
    }

    function testForkAttributeMutationsRejected() public {
        // These mutations invalidate signatures and may reject before policy.
        // They do not substitute for authenticated debug hardware samples.
        bytes memory quote = vm.parseJsonBytes(_fixture("ata-sgx-v3"), ".quote");
        quote[96] |= 0x02;
        _rejectRaw(quote, 20);
        quote = vm.parseJsonBytes(_fixture("ata-tdx-v4"), ".quote");
        quote[168] |= 0x01;
        _rejectRaw(quote, 20);
    }

    function testForkHistoricalAlibabaQuoteRejected() public {
        // Historical input can fail collateral checks before production policy.
        // Keep the observed reason; do not claim a policy-specific success here.
        _upsert(_fixture("ata-tdx-v4")); // Refresh shared signed TDX QE/cert collateral.
        bytes memory quote = vm.readFileBinary("forge-test/assets/quotes/alibaba_quote_5.dat");
        (bool called, bytes memory returned) = address(fee).call{value: 1 ether}(
            abi.encodeWithSignature("verifyAndAttestOnChainV2(bytes,uint32)", quote, uint32(20)));
        if (called) {
            (bool success, bytes memory reason) = abi.decode(returned, (bool, bytes));
            assertFalse(success, "historical migration-service input accepted");
            assertEq(reason, bytes("TCBR"), "unexpected pre-policy failure");
            console2.log("historical Alibaba fork rejection", string(reason));
        } else {
            assertEq(returned, abi.encodeWithSignature("Error(string)",
                "TDX migration service TD measurement is not zero"), "unexpected policy revert");
            console2.log("authentic Alibaba migration-service policy rejection confirmed");
        }
        _rejectRaw(quote, 20);
    }

    function testForkFeePaymentRefundAndWithdrawal() public {
        string memory fixture = _fixture("ata-sgx-v3");
        uint32 eval = _upsert(fixture);
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        uint16 oldBp = fee.getBp();
        vm.prank(owner); fee.setBp(500);
        address payer = makeAddr("fork-only-fee-payer");
        vm.deal(payer, 10 ether);
        vm.prank(payer, payer);
        vm.expectRevert(bytes4(keccak256("Insufficient_Funds()")));
        fee.verifyAndAttestOnChainV2(quote, eval);
        uint256 beforeBalance = payer.balance;
        uint256 beforeCollected = address(fee).balance;
        vm.prank(payer, payer);
        (bool success,) = fee.verifyAndAttestOnChainV2{value: 0.1 ether}(quote, eval);
        assertTrue(success);
        uint256 collected = address(fee).balance - beforeCollected;
        assertGt(collected, 0);
        assertLt(collected, 0.1 ether);
        assertEq(beforeBalance - payer.balance, collected, "excess not refunded to payer");
        address beneficiary = makeAddr("fork-only-fee-beneficiary");
        vm.expectRevert(); fee.withdraw(beneficiary, collected);
        vm.prank(owner); fee.withdraw(beneficiary, collected);
        assertEq(beneficiary.balance, collected);
        assertEq(address(fee).balance, beforeCollected);
        vm.prank(owner); fee.setBp(oldBp);
        assertEq(fee.getBp(), legacy.getBp(), "live fee settings not restored");
    }

    function _switchHelper(address target) internal {
        vm.prank(owner);
        router.setConfig(original[0], original[1], original[2], target, original[4], original[5]);
    }

    function _legacyCoexistence(string memory name) internal {
        string memory fixture = _fixture(name);
        uint32 eval = _upsert(fixture);
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        _switchHelper(original[3]);
        (bool oldSuccess, bytes memory oldOutput) = legacy.verifyAndAttestOnChain{value: 1 ether}(quote, eval);
        assertTrue(oldSuccess, string.concat("deployed legacy baseline failed: ", string(oldOutput)));
        _switchHelper(helper);
        (bool success, bytes memory output) = legacy.verifyAndAttestOnChain{value: 1 ether}(quote, eval);
        assertTrue(success, string(output));
        assertEq(output, oldOutput, "helper switch changed deployed legacy output");
        (success, output) = fee.verifyAndAttestOnChain{value: 1 ether}(quote, eval);
        assertTrue(success, string(output));
        assertEq(output, oldOutput, "FeeV2 legacy selector changed output");
        (success,) = fee.verifyAndAttestOnChainV2{value: 1 ether}(quote, eval);
        assertTrue(success, "V2 baseline before rollback failed");
        // Exercise caller behavior, not only restored Router addresses. The old
        // helper has no combined V2 parser; legacy consumers remain available.
        _switchHelper(original[3]);
        (success, output) = legacy.verifyAndAttestOnChain{value: 1 ether}(quote, eval);
        assertTrue(success, string(output));
        assertEq(output, oldOutput, "legacy application unavailable after rollback");
        (success, output) = fee.verifyAndAttestOnChain{value: 1 ether}(quote, eval);
        assertTrue(success, string(output));
        assertEq(output, oldOutput, "FeeV2 old selector unavailable after rollback");
        _rejectRaw(quote, eval);
        _switchHelper(helper);
        (success,) = fee.verifyAndAttestOnChainV2{value: 1 ether}(quote, eval);
        assertTrue(success, "V2 rollout replay failed");
    }

    function testForkLegacySgxCoexistenceAndRollback() public { _legacyCoexistence("ata-sgx-v3"); }
    function testForkLegacyTdxV4CoexistenceAndRollback() public { _legacyCoexistence("ata-tdx-v4"); }
    function testForkLegacyTdxV5CoexistenceAndRollback() public { _legacyCoexistence("v5"); }

    function _assertSuccessEvent(Vm.Log[] memory logs, ZkCoProcessorType backend, bytes memory journal) internal view {
        uint256 found;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(fee) || logs[i].topics[0] != V2_EVENT) continue;
            assertEq(logs[i].topics.length, 3);
            assertEq(uint256(logs[i].topics[1]), 2);
            assertEq(uint256(logs[i].topics[2]), 1);
            (bool success, ZkCoProcessorType actual, bytes memory output) = abi.decode(logs[i].data, (bool, ZkCoProcessorType, bytes));
            assertTrue(success); assertEq(uint256(actual), uint256(backend)); assertEq(output, journal);
            ++found;
        }
        assertEq(found, 1, "expected exactly one identity-bearing event");
    }

    function _rejectRaw(bytes memory quote, uint32 eval) internal {
        _rejectCall(abi.encodeWithSignature("verifyAndAttestOnChainV2(bytes,uint32)", quote, eval));
    }

    function _rejectCall(bytes memory data) internal {
        vm.recordLogs();
        // Pay enough so a negative cannot pass solely on Insufficient_Funds.
        (bool ok, bytes memory result) = address(fee).call{value: 1 ether}(data);
        if (ok) { (bool accepted,) = abi.decode(result, (bool,bytes)); assertFalse(accepted, "negative accepted"); }
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(fee) || logs[i].topics.length == 0 || logs[i].topics[0] != V2_EVENT) continue;
            (bool accepted,,) = abi.decode(logs[i].data, (bool, ZkCoProcessorType, bytes));
            assertFalse(accepted, "negative emitted accepted event");
        }
    }

    function testForkRawMissingAuthorizationAndEvaluation() public {
        string memory fixture = _fixture("ata-sgx-v3");
        uint32 eval = _upsert(fixture);
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        (bool success,) = fee.verifyAndAttestOnChainV2{value: 1 ether}(quote, eval);
        assertTrue(success, "negative baseline failed");
        _rejectRaw(quote, type(uint32).max);
        // A revoked allowlist entry is only a negative when restrictions are
        // enabled. Public-reader mode is a legitimate existing live setting.
        vm.prank(owner); router.enableCallerRestriction();
        vm.prank(owner); router.setAuthorized(verifiers[0], false);
        _rejectRaw(quote, eval);
        vm.prank(owner); router.setAuthorized(verifiers[0], true);
        (success,) = fee.verifyAndAttestOnChainV2{value: 1 ether}(quote, eval);
        assertTrue(success, "authorization restore failed");
    }

    function testForkRealProof() public {
        string memory proofFile = vm.envOr("DCAP_FORK_PROOF_FILE", string(""));
        if (bytes(proofFile).length == 0) { vm.skip(true, "real EVM proof not supplied; not a proof success"); return; }
        string memory fixture = _fixture(vm.envOr("DCAP_FORK_FIXTURE", string("ata-sgx-v3")));
        uint32 eval = _upsert(fixture);
        string memory payload = vm.readFile(proofFile);
        ZkCoProcessorType kind = ZkCoProcessorType(vm.parseJsonUint(payload, ".backend"));
        require(kind == ZkCoProcessorType.RiscZero || kind == ZkCoProcessorType.Succinct, "production backend only");
        bytes32 id = vm.parseJsonBytes32(payload, ".programId");
        assertEq(id, fee.programIdentifierV2(kind), "unexpected program ID");
        bytes memory journal = vm.parseJsonBytes(payload, ".journal");
        bytes memory proof = vm.parseJsonBytes(payload, ".proof");
        assertEq(journal, vm.parseJsonBytes(fixture, ".expectedJournal"));
        vm.prank(owner); fee.setZkV2Paused(false);
        vm.recordLogs();
        uint256 beforeGas = gasleft();
        (bool success, bytes memory output) = fee.verifyAndAttestWithZKProofV2{value: 1 ether}(journal, kind, proof, id, eval);
        console2.log("ZK verification internal-call gas", beforeGas - gasleft());
        assertTrue(success, string(output));
        assertEq(output, journal);
        _assertSuccessEvent(vm.getRecordedLogs(), kind, journal);
        uint256 validState = vm.snapshotState();
        OutputV2 memory decoded = this.decode(journal);
        FmspcTcbDao tcb = FmspcTcbDao(router.fmspcTcbDaoVersionedAddr(eval));
        EnclaveIdentityDao qe = EnclaveIdentityDao(router.qeIdDaoVersionedAddr(eval));
        (, uint64 tcbExpiry) = tcb.getCollateralValidity(
            tcb.FMSPC_TCB_KEY(decoded.quoteBodyType == 1 ? 0 : 1, decoded.fmspc, 3));
        (, uint64 qeExpiry) = qe.getCollateralValidity(
            qe.ENCLAVE_ID_KEY(decoded.quoteBodyType == 1 ? 0 : 2, 4));
        uint256 expiry = tcbExpiry > qeExpiry ? tcbExpiry : qeExpiry;
        assertGt(expiry, chainTimestamp, "expected valid signed proof collateral");
        // ZK collateral is checked at the authenticated journal timestamp, not
        // submission time. Merely advancing the current block must NOT impose
        // an unagreed maximum-age/challenge policy on a historical proof.
        vm.warp(expiry + 1);
        (success, output) = fee.verifyAndAttestWithZKProofV2{value: 1 ether}(journal, kind, proof, id, eval);
        assertTrue(success, "unexpected journal maximum-age policy");
        assertEq(output, journal, "historical journal changed");
        assertTrue(vm.revertToState(validState));
        if (kind == ZkCoProcessorType.Succinct && block.chainid == 11155111) {
            _existingSp1Freezes(journal, proof, id, eval);
        }
        bytes memory changed = bytes.concat(proof);
        changed[changed.length - 1] ^= 0x01;
        _rejectProof(journal, kind, changed, id, eval);
        changed = bytes.concat(journal);
        changed[25] ^= 0x01;
        _rejectProof(changed, kind, proof, id, eval);
        changed = bytes.concat(journal);
        changed[1] ^= 0x01; // unsupported major format version, not quote version
        _rejectProof(changed, kind, proof, id, eval);
        _rejectProof(journal, kind, proof, bytes32(uint256(id) ^ 1), eval);
        _rejectProof(journal, kind, proof, legacy.programIdentifier(kind), eval);
        ZkCoProcessorType other = kind == ZkCoProcessorType.RiscZero
            ? ZkCoProcessorType.Succinct : ZkCoProcessorType.RiscZero;
        _rejectProof(journal, other, proof, fee.programIdentifierV2(other), eval);
        _rejectProof(journal, kind, hex"01", id, eval);
        _rejectProof(journal, kind, proof, id, type(uint32).max);
        vm.prank(owner); fee.setZkV2Paused(true);
        _rejectProof(journal, kind, proof, id, eval);
        vm.prank(owner); fee.setZkV2Paused(false);
        vm.prank(owner); fee.freezeVerifyRoute(kind, bytes4(proof));
        _rejectProof(journal, kind, proof, id, eval);
    }

    function _rejectProof(bytes memory journal, ZkCoProcessorType kind, bytes memory proof, bytes32 id, uint32 eval) internal {
        _rejectCall(abi.encodeWithSignature("verifyAndAttestWithZKProofV2(bytes,uint8,bytes,bytes32,uint32)", journal, kind, proof, id, eval));
    }

    function _existingSp1Freezes(bytes memory journal, bytes memory proof, bytes32 id, uint32 eval) internal {
        // Existing immutable freezes observed in the pinned Sepolia gateway's
        // complete route history. No owner impersonation or gateway mutation.
        IForkSp1Gateway gateway = IForkSp1Gateway(legacy.zkVerifier(ZkCoProcessorType.Succinct));
        for (uint256 i; i < 2; ++i) {
            bytes4 selector = i == 0 ? bytes4(0x09069090) : bytes4(0x2b4aeaf7);
            (address verifier, bool frozen) = gateway.routes(selector);
            assertTrue(verifier.code.length != 0 && frozen, "existing universal freeze missing");
            bytes memory changed = bytes.concat(proof);
            for (uint256 j; j < 4; ++j) changed[j] = selector[j];
            vm.expectRevert(abi.encodeWithSignature("RouteIsFrozen(bytes4)", selector));
            gateway.verifyProof(id, journal, changed);
            _rejectProof(journal, ZkCoProcessorType.Succinct, changed, id, eval);
        }
        console2.log("existing SP1 universal freezes preserved and rejected", uint256(2));
    }
}
