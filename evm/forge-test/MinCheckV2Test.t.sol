// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "./AttestationFeeV2Test.t.sol";

/// Mode-routing unit tests use mocks; real quote authentication is tested by the fixture suites.
contract MinCheckV2Test is AttestationFeeV2Test {
    function _exercise(uint16 kind, bytes memory body, string memory reason) internal {
        uint16 version = kind == 1 ? 3 : (kind == 2 ? 4 : 5);
        quote.configure(version, kind, body, 0);
        fee.setQuoteVerifier(address(quote));
        bytes memory raw = bytes.concat(bytes1(uint8(version)), new bytes(47));
        vm.expectRevert(bytes(reason));
        fee.verifyAndAttestOnChainV2(raw);
        vm.expectRevert(bytes(reason));
        fee.verifyAndAttestOnChainV2(raw, 17, false);
        (bool success, bytes memory output) = fee.verifyAndAttestOnChainV2(raw, 17, true);
        assertTrue(success);
        assertEq(this.decode(output).quoteBody, body);
        assertEq(this.decode(output).fullQuoteHash, keccak256(raw));
        universal.expectProof(V2_ID, output);
        for (uint8 i = 1; i <= 3; ++i) {
            ZkCoProcessorType backend = ZkCoProcessorType(i);
            bytes memory proof = i == 3 ? new bytes(260) : new bytes(4);
            vm.expectRevert(bytes(reason));
            fee.verifyAndAttestWithZKProofV2(output, backend, proof);
            vm.expectRevert(bytes(reason));
            fee.verifyAndAttestWithZKProofV2(output, backend, proof, V2_ID, 17, false);
            bytes memory verified;
            (success, verified) = fee.verifyAndAttestWithZKProofV2(output, backend, proof, V2_ID, 17, true);
            assertTrue(success);
            assertEq(verified, output);
        }
    }

    function testSgxDebugModes() public {
        bytes memory body = new bytes(384);
        body[48] = 0x02;
        _exercise(1, body, "SGX debug mode is enabled");
    }

    function testTdxAttributeModes() public {
        for (uint16 kind = 2; kind <= 3; ++kind) {
            bytes memory body = new bytes(kind == 2 ? 584 : 648);
            _exercise(kind, body, "TDX SEPT_VE_DISABLE is not enabled");
            body[123] = 0x10;
            body[120] = 0x01;
            _exercise(kind, body, "TDX debug mode is enabled");
            body[120] = 0x02;
            _exercise(kind, body, "reserved TDX attribute bits are set");
            if (kind == 3) {
                body[120] = 0;
                body[600] = 0x01;
                _exercise(kind, body, "TDX migration service TD measurement is not zero");
            }
        }
    }

    function testMinimalStillRejectsStatusProofIdCollateralPauseAndMalformedJournal() public {
        bytes memory output = journal();
        for (uint8 status = 6; status <= 7; ++status) {
            quote.configure(3, 1, new bytes(384), status);
            vm.expectRevert(bytes("Invalid V2 TCB status"));
            fee.verifyAndAttestOnChainV2(quoteBytes(), 17, true);
            bytes memory bad = bytes.concat(output);
            bad[9] = bytes1(status);
            universal.expectProof(V2_ID, bad);
            (bool accepted,) = fee.verifyAndAttestWithZKProofV2(bad, ZkCoProcessorType.RiscZero, new bytes(4), V2_ID, 17, true);
            assertFalse(accepted);
        }
        universal.expectProof(V2_ID, output);
        (bool success,) = fee.verifyAndAttestWithZKProofV2(output, ZkCoProcessorType.RiscZero, new bytes(4), LEGACY_ID, 17, true);
        assertFalse(success);
        bytes memory changed = bytes.concat(output);
        changed[25] ^= 0x01;
        vm.expectRevert(bytes("bad proof"));
        fee.verifyAndAttestWithZKProofV2(changed, ZkCoProcessorType.RiscZero, new bytes(4), V2_ID, 17, true);
        changed = bytes.concat(output);
        changed[65] ^= 0x01;
        universal.expectProof(V2_ID, changed);
        (success,) = fee.verifyAndAttestWithZKProofV2(changed, ZkCoProcessorType.RiscZero, new bytes(4), V2_ID, 17, true);
        assertFalse(success);
        vm.expectRevert();
        fee.verifyAndAttestWithZKProofV2(bytes.concat(output, hex"00"), ZkCoProcessorType.RiscZero, new bytes(4), V2_ID, 17, true);
        fee.setZkV2Paused(true);
        (success,) = fee.verifyAndAttestWithZKProofV2(output, ZkCoProcessorType.RiscZero, new bytes(4), V2_ID, 17, true);
        assertFalse(success);
    }
}
