// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "./AutomataDcapOnChainAttestationTest.t.sol";
import {DeployDcapV2} from "../forge-script/DeployDcapV2.s.sol";
import {AutomataDcapAttestationV2} from "../contracts/AutomataDcapAttestationV2.sol";
import {FeeV2UniversalMock} from "./AttestationFeeV2Test.t.sol";

contract RolloutV2Test is AutomataDcapOnChainAttestationTest {
    function testLocalRolloutPreservesLegacyAndOtherRouterComponents() public {
        DeployDcapV2 script = new DeployDcapV2();
        address oldHelper = pccsRouter.pckHelperAddr();
        DeployDcapV2.Deployment memory d = script.deploy(admin, address(pccsRouter), P256_VERIFIER);
        script.configure(admin, pccsRouter, attestation, d);
        AutomataDcapAttestationV2 attestationV2 = AutomataDcapAttestationV2(d.attestation);
        assertTrue(attestationV2.zkV2Paused());
        assertEq(pccsRouter.pckHelperAddr(), oldHelper);
        assertEq(address(attestation.quoteVerifiers(3)), address(0));
        script.switchHelper(admin, pccsRouter, oldHelper, d.helper);
        assertEq(pccsRouter.pckHelperAddr(), d.helper);
        assertEq(pccsRouter.pcsDaoAddr(), address(pcsDao));
        assertEq(pccsRouter.pckDaoAddr(), address(pckDao));
        assertEq(pccsRouter.crlHelperAddr(), address(x509Crl));
        assertEq(pccsRouter.fmspcTcbHelperAddr(), address(tcbHelper));
        assertEq(pccsRouter.tcbEvalDaoAddr(), address(tcbEvalDao));
        script.switchHelper(admin, pccsRouter, d.helper, oldHelper);
        assertEq(pccsRouter.pckHelperAddr(), oldHelper);
    }

    function testV2ProgramRegistrationDoesNotMigrateLegacyPrograms() public {
        FeeV2UniversalMock universal = new FeeV2UniversalMock();
        vm.startPrank(admin);
        AutomataDcapAttestationV2 attestationV2 = new AutomataDcapAttestationV2(admin);
        attestation.setZkConfiguration(
            ZkCoProcessorType.RiscZero, ZkCoProcessorConfig(bytes32(uint256(1)), address(universal))
        );
        attestation.updateProgramIdentifier(ZkCoProcessorType.RiscZero, bytes32(uint256(2)));
        attestation.freezeVerifyRoute(ZkCoProcessorType.RiscZero, hex"deadbeef");
        vm.stopPrank();
        vm.prank(admin);
        attestationV2.setZkV2Paused(true);
        DeployDcapV2 script = new DeployDcapV2();
        script.configureV2Backend(
            admin, attestationV2, ZkCoProcessorType.RiscZero, bytes32(uint256(3)), address(universal)
        );
        script.configureMinimalProgram(admin, attestationV2, ZkCoProcessorType.RiscZero, bytes32(uint256(4)));
        assertEq(attestationV2.programIdentifiersV2(ZkCoProcessorType.RiscZero).length, 2);
        assertEq(attestationV2.programIdentifierV2(ZkCoProcessorType.RiscZero), bytes32(uint256(3)));
        (bool registered,) = attestationV2.programModeV2(ZkCoProcessorType.RiscZero, bytes32(uint256(2)));
        assertFalse(registered);
        assertEq(attestation.programIdentifier(ZkCoProcessorType.RiscZero), bytes32(uint256(2)));
    }
}
