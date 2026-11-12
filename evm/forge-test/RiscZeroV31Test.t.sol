// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {AutomataDcapAttestationV2} from "../contracts/AutomataDcapAttestationV2.sol";
import {ZkCoProcessorType} from "../contracts/AttestationEntrypointBase.sol";
import {TestReceipt as CurrentReceipt} from "../lib/risc0-ethereum/contracts/test/TestReceiptV3_1.sol";
import {TestReceipt as OldReceipt} from "../lib/risc0-ethereum/contracts/test/TestReceiptV3_0.sol";

/// Upstream cryptographic controls, not DCAP guest acceptance evidence.
contract RiscZeroV31Test is Test {
    IRiscZeroVerifier internal verifier;

    function setUp() public virtual {
        RiscZeroGroth16Verifier fresh = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
        assertEq(fresh.SELECTOR(), bytes4(0xe71e6620));
        verifier = fresh;
    }

    function testRepairedCircuitAcceptsRealUpstreamReceipt() public view {
        verifier.verify(CurrentReceipt.SEAL, CurrentReceipt.IMAGE_ID, sha256(CurrentReceipt.JOURNAL));
    }

    function testOldReceiptRejectedEvenIfSelectorIsRelabeled() public view virtual {
        _reject(OldReceipt.SEAL, OldReceipt.IMAGE_ID, sha256(OldReceipt.JOURNAL));
        bytes memory changed = OldReceipt.SEAL;
        bytes4 selector = 0xe71e6620;
        for (uint256 i; i < 4; ++i) changed[i] = selector[i];
        _reject(changed, OldReceipt.IMAGE_ID, sha256(OldReceipt.JOURNAL));
    }

    function testWrongImageJournalAndSealRejected() public view {
        _reject(CurrentReceipt.SEAL, bytes32(uint256(CurrentReceipt.IMAGE_ID) ^ 1), sha256(CurrentReceipt.JOURNAL));
        _reject(CurrentReceipt.SEAL, CurrentReceipt.IMAGE_ID, sha256(bytes.concat(CurrentReceipt.JOURNAL, hex"01")));
        bytes memory changed = CurrentReceipt.SEAL;
        changed[changed.length - 1] ^= 0x01;
        _reject(changed, CurrentReceipt.IMAGE_ID, sha256(CurrentReceipt.JOURNAL));
    }

    function _reject(bytes memory seal, bytes32 id, bytes32 journalDigest) internal view {
        (bool ok,) = address(verifier).staticcall(abi.encodeCall(IRiscZeroVerifier.verify, (seal, id, journalDigest)));
        assertFalse(ok, "invalid receipt accepted");
    }
}

contract RiscZeroV31HoodiForkTest is RiscZeroV31Test {
    function setUp() public override {
        string memory rpc = vm.envOr("DCAP_FORK_RPC", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true, "Hoodi RPC required; not fork acceptance");
            return;
        }
        vm.createSelectFork(rpc, vm.envUint("DCAP_FORK_BLOCK"));
        // Run with FOUNDRY_PROFILE=fork_osaka; the deployed router uses modern opcodes.
        assertEq(block.chainid, 560048, "Hoodi only");
        // Official router, including its emergency-stop wrapper; no mocks or etching.
        verifier = IRiscZeroVerifier(0x32Db7dc407AC886807277636a1633A1381748DD8);
        RiscZeroGroth16Verifier direct = RiscZeroGroth16Verifier(0x8c915b5071206C6E328BC18529586c513408aB3b);
        assertEq(direct.SELECTOR(), bytes4(0xe71e6620));
        assertEq(direct.VERSION(), "3.1.0");
    }

    // Old routes may still be live upstream during the grace period. The V2
    // entrypoint rejects them independently; this test targets the repaired route.
    function testOldReceiptRejectedEvenIfSelectorIsRelabeled() public view override {
        bytes memory changed = OldReceipt.SEAL;
        bytes4 selector = 0xe71e6620;
        for (uint256 i; i < 4; ++i) changed[i] = selector[i];
        _reject(changed, OldReceipt.IMAGE_ID, sha256(OldReceipt.JOURNAL));
    }

    function testV2BlocksHistoricalReceiptBeforeLiveRouterInBothModes() public {
        for (uint256 mode; mode < 2; ++mode) {
            AutomataDcapAttestationV2 entry = new AutomataDcapAttestationV2(address(this));
            entry.setBp(0);
            entry.setZkVerifierV2(ZkCoProcessorType.RiscZero, address(verifier));
            entry.addVerifyRoute(ZkCoProcessorType.RiscZero, 0xe71e6620, address(verifier));
            entry.addProgramIdentifierV2(ZkCoProcessorType.RiscZero, OldReceipt.IMAGE_ID, mode == 1);
            if (mode == 0) entry.setDefaultProgramIdentifierV2(ZkCoProcessorType.RiscZero, OldReceipt.IMAGE_ID);
            (bool ok, bytes memory reason) = entry.verifyAndAttestWithZKProofV2(
                OldReceipt.JOURNAL, ZkCoProcessorType.RiscZero, OldReceipt.SEAL, OldReceipt.IMAGE_ID, 0, mode == 1
            );
            assertFalse(ok);
            assertEq(string(reason), "ZK Verifier is not configured");
            entry.freezeVerifyRoute(ZkCoProcessorType.RiscZero, bytes4(OldReceipt.SEAL));
            vm.expectRevert(abi.encodeWithSignature("ZK_Route_Frozen(uint8,bytes4)", uint8(1), bytes4(OldReceipt.SEAL)));
            entry.verifyAndAttestWithZKProofV2(
                OldReceipt.JOURNAL, ZkCoProcessorType.RiscZero, OldReceipt.SEAL, OldReceipt.IMAGE_ID, 0, mode == 1
            );
        }
    }
}
