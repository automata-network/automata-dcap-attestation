// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

import {AutomataDcapAttestationFee} from "../contracts/AutomataDcapAttestationFee.sol";
import {PCCSRouter} from "../contracts/PCCSRouter.sol";
import {CA} from "@automata-network/on-chain-pccs/Common.sol";
import {PcsDao} from "@automata-network/on-chain-pccs/bases/PcsDao.sol";
import {PcsDaoV2} from "@automata-network/on-chain-pccs/bases/PcsDaoV2.sol";
import {AutomataDaoStorage} from "@automata-network/on-chain-pccs/automata_pccs/shared/AutomataDaoStorage.sol";
import {AutomataPcsDaoV2} from "@automata-network/on-chain-pccs/automata_pccs/AutomataPcsDaoV2.sol";
import {AutomataPckDaoV2} from "@automata-network/on-chain-pccs/automata_pccs/AutomataPckDaoV2.sol";
import {
    PccsDependencyConfig
} from "@automata-network/on-chain-pccs/automata_pccs/shared/PccsDependencyConfig.sol";
import {X509CRLHelperV2} from "@automata-network/on-chain-pccs/helpers/X509CRLHelperV2.sol";

contract CrlV2AeneidForkTest is Test {
    address internal constant ROUTER_ADDR = 0xcb1934EA19c6650a8cC9888c0306D39f0BeBc2AB;
    address internal constant ATTESTATION_ADDR = 0xB8621Da79b42A62E576408995155D48E9f856489;
    address internal constant P256_SHIM_ADDR = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    uint32 internal constant TCB_EVALUATION_NUMBER = 19;

    PCCSRouter internal router;
    AutomataDcapAttestationFee internal attestation;
    AutomataDaoStorage internal storageContract;
    AutomataPcsDaoV2 internal pcsV2;
    AutomataPckDaoV2 internal pckV2;
    PccsDependencyConfig internal dependencyConfig;
    X509CRLHelperV2 internal crlV2;
    bytes internal crl57;
    bytes internal crl129;

    function setUp() public {
        string memory storyRpcUrl = vm.envOr("STORY_RPC_URL", string(""));
        if (bytes(storyRpcUrl).length == 0) {
            vm.skip(true, "STORY_RPC_URL is required for the Aeneid fork suite");
        }
        vm.createSelectFork(storyRpcUrl);
        crl57 = vm.parseBytes(vm.readLine("forge-test/assets/crl/platform-57-20260716.hex"));
        crl129 = vm.parseBytes(vm.readLine("forge-test/assets/crl/platform-129-20260716.hex"));

        router = PCCSRouter(ROUTER_ADDR);
        attestation = AutomataDcapAttestationFee(ATTESTATION_ADDR);

        PcsDao oldPcs = PcsDao(router.pcsDaoAddr());
        storageContract = AutomataDaoStorage(address(oldPcs.resolver()));
        address p256 = oldPcs.P256_VERIFIER();

        // Foundry's local EVM does not currently materialize Story's RIP-7212
        // precompile when forking. Reuse the deployed audited shim bytecode.
        if (p256.code.length == 0) {
            bytes memory shimCode = P256_SHIM_ADDR.code;
            require(shimCode.length > 0, "missing P256 shim");
            vm.etch(p256, shimCode);
        }

        crlV2 = new X509CRLHelperV2(storageContract.owner());
        dependencyConfig = new PccsDependencyConfig(storageContract.owner());
        pcsV2 =
            new AutomataPcsDaoV2(address(storageContract), p256, router.pckHelperAddr(), address(dependencyConfig));
        vm.prank(storageContract.owner());
        dependencyConfig.initialize(address(pcsV2), address(crlV2));
        pckV2 =
            new AutomataPckDaoV2(address(storageContract), p256, address(dependencyConfig), router.pckHelperAddr());

        vm.startPrank(storageContract.owner());
        storageContract.grantDao(address(pcsV2));
        storageContract.grantDao(address(pckV2));
        crlV2.setAuthorizedIndexer(address(pcsV2), true);
        vm.stopPrank();

        vm.startPrank(router.owner());
        router.setConfig(
            router.tcbEvalDaoAddr(),
            address(pcsV2),
            address(pckV2),
            router.pckHelperAddr(),
            address(crlV2),
            router.fmspcTcbHelperAddr()
        );
        vm.stopPrank();

        assertEq(router.pcsDaoAddr(), address(pcsV2));
        assertEq(router.pckDaoAddr(), address(pckV2));
        assertEq(router.crlHelperAddr(), address(crlV2));
    }

    function testForkUpsert57And129ShrinkRollbackAndGas() public {
        uint256 initialState = vm.snapshotState();

        uint256 before57 = gasleft();
        pcsV2.upsertPckCrl(CA.PLATFORM, crl57);
        uint256 initial57Gas = before57 - gasleft();
        _assertStoredCrl(crl57);
        assertTrue(crlV2.indexedCrls(keccak256(crl57)));

        assertTrue(vm.revertToState(initialState));

        uint256 before129 = gasleft();
        pcsV2.upsertPckCrl(CA.PLATFORM, crl129);
        uint256 initial129Gas = before129 - gasleft();
        _assertStoredCrl(crl129);
        assertTrue(crlV2.indexedCrls(keccak256(crl129)));

        uint256 beforeShrink = gasleft();
        pcsV2.upsertPckCrl(CA.PLATFORM, crl57);
        uint256 shrink57Gas = beforeShrink - gasleft();
        _assertStoredCrl(crl57);
        assertTrue(crlV2.indexedCrls(keccak256(crl57)));

        vm.expectRevert(PcsDaoV2.Certificate_Out_Of_Date.selector);
        pcsV2.upsertPckCrl(CA.PLATFORM, crl129);
        _assertStoredCrl(crl57);

        console2.log("fork V2 57-entry initial upsert gas", initial57Gas);
        console2.log("fork V2 129-entry initial upsert gas", initial129Gas);
        console2.log("fork V2 129-to-57 replacement gas", shrink57Gas);
    }

    function testForkIndexesCrlAlreadyStoredByLegacyDao() public {
        bytes memory existingCrl = router.getCrl(CA.PLATFORM);
        bytes32 derHash = keccak256(existingCrl);
        assertFalse(crlV2.indexedCrls(derHash));

        uint256 beforeMigration = gasleft();
        uint256 indexedCount = pcsV2.indexStoredCrl(CA.PLATFORM, derHash);
        uint256 migrationGas = beforeMigration - gasleft();
        assertGt(indexedCount, 0);
        assertTrue(crlV2.indexedCrls(derHash));
        _assertStoredCrl(existingCrl);

        console2.log("fork V1 stored PLATFORM CRL atomic migration gas", migrationGas);
    }

    function testForkUpsert129CompletesExactIndexInSameTransaction() public {
        bytes32 derHash = keccak256(crl129);
        uint256 beforeUpsert = gasleft();
        pcsV2.upsertPckCrl(CA.PLATFORM, crl129);
        uint256 upsertGas = beforeUpsert - gasleft();

        assertTrue(crlV2.indexedCrls(derHash));

        console2.log("fork V2 129-entry atomic upsert+index gas", upsertGas);
    }

    function testForkRealSigned57EntryReissueReusesExactIndex() public {
        bytes memory previousCrl = router.getCrl(CA.PLATFORM);
        bytes32 previousDerHash = keccak256(previousCrl);
        bytes32 currentDerHash = keccak256(crl57);
        assertNotEq(previousDerHash, currentDerHash, "expected different signed CRLs");

        pcsV2.indexStoredCrl(CA.PLATFORM, previousDerHash);
        bytes32 previousSetHash = crlV2.crlRevokedSetHashes(previousDerHash);

        uint256 beforeReissue = gasleft();
        pcsV2.upsertPckCrl(CA.PLATFORM, crl57);
        uint256 reissueGas = beforeReissue - gasleft();

        assertEq(crlV2.crlRevokedSetHashes(currentDerHash), previousSetHash, "serial set index was not reused");
        assertTrue(crlV2.indexedCrls(currentDerHash));
        _assertStoredCrl(crl57);

        console2.log("fork V2 real-signed 57-entry exact-set reuse upsert gas", reissueGas);
    }

    function testForkReplayProvidedQuoteAgainst57And129Crl() public {
        bytes memory quote = vm.envOr("QUOTE_HEX", bytes(""));
        if (quote.length == 0) {
            vm.skip(true, "QUOTE_HEX is required for quote replay");
        }
        uint256 initialState = vm.snapshotState();

        pcsV2.upsertPckCrl(CA.PLATFORM, crl57);
        assertTrue(crlV2.indexedCrls(keccak256(crl57)));
        (uint256 verify57IndexedGas, bool success57, bytes memory output57) = _verifyQuote(quote);
        assertTrue(success57, string(output57));

        assertTrue(vm.revertToState(initialState));

        pcsV2.upsertPckCrl(CA.PLATFORM, crl129);
        assertTrue(crlV2.indexedCrls(keccak256(crl129)));
        (uint256 verify129IndexedGas, bool success129, bytes memory output129) = _verifyQuote(quote);
        assertTrue(success129, string(output129));

        console2.log("fork V2 verify 57-entry indexed gas", verify57IndexedGas);
        console2.log("fork V2 verify 129-entry indexed gas", verify129IndexedGas);
    }

    function _verifyQuote(bytes memory quote) private returns (uint256 gasUsed, bool success, bytes memory output) {
        uint256 before = gasleft();
        (success, output) = attestation.verifyAndAttestOnChain(quote, TCB_EVALUATION_NUMBER);
        gasUsed = before - gasleft();
    }

    function _assertStoredCrl(bytes memory expected) private {
        bytes memory actual = router.getCrl(CA.PLATFORM);
        assertEq(actual, expected);
    }
}
