// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "./AutomataDcapOnChainAttestationTest.t.sol";
import {DeployDcapV2} from "../forge-script/DeployDcapV2.s.sol";
import {AutomataDcapAttestationFeeV2} from "../contracts/AutomataDcapAttestationFeeV2.sol";
import {FeeV2UniversalMock} from "./AttestationFeeV2Test.t.sol";

contract RolloutV2Test is AutomataDcapOnChainAttestationTest {
    function testLocalRolloutPreservesLegacyAndOtherRouterComponents() public {
        DeployDcapV2 script = new DeployDcapV2();
        address oldHelper = pccsRouter.pckHelperAddr();
        DeployDcapV2.Deployment memory d = script.deploy(admin, address(pccsRouter), P256_VERIFIER);
        script.configure(admin, pccsRouter, attestation, d);
        AutomataDcapAttestationFeeV2 fee = AutomataDcapAttestationFeeV2(d.fee);
        assertTrue(fee.zkV2Paused());
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

    function testLegacyProgramAndFrozenRouteMigration() public {
        FeeV2UniversalMock universal = new FeeV2UniversalMock();
        vm.startPrank(admin);
        AutomataDcapAttestationFeeV2 fee = new AutomataDcapAttestationFeeV2(admin);
        attestation.setZkConfiguration(
            ZkCoProcessorType.RiscZero, ZkCoProcessorConfig(bytes32(uint256(1)), address(universal))
        );
        attestation.updateProgramIdentifier(ZkCoProcessorType.RiscZero, bytes32(uint256(2)));
        attestation.freezeVerifyRoute(ZkCoProcessorType.RiscZero, hex"deadbeef");
        vm.stopPrank();
        bytes4[] memory routes = new bytes4[](1);
        routes[0] = hex"deadbeef";
        DeployDcapV2 script = new DeployDcapV2();
        script.migrateLegacyBackend(admin, attestation, fee, ZkCoProcessorType.RiscZero, routes);
        assertEq(fee.programIdentifiers(ZkCoProcessorType.RiscZero).length, 2);
        assertEq(fee.programIdentifier(ZkCoProcessorType.RiscZero), bytes32(uint256(2)));
        assertEq(fee.programIdentifierV2(ZkCoProcessorType.RiscZero), bytes32(0));
        vm.expectRevert();
        fee.zkVerifier(ZkCoProcessorType.RiscZero, hex"deadbeef");
    }
}
