// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./utils/PCCSSetupBase.sol";

import {CA} from "@automata-network/on-chain-pccs/Common.sol";
import {EnclaveId} from "@automata-network/on-chain-pccs/helpers/EnclaveIdentityHelper.sol";
import {TcbId} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";

contract PCCSRouterVersioningTest is PCCSSetupBase {
    PCCSRouter pccsRouter;
    bytes6 constant FMSPC_TDX = bytes6(uint48(0x00806f050000));

    function setUp() public override {
        vm.warp(1749095100);
        super.setUp();

        vm.startPrank(admin);
        pccsRouter = setupPccsRouter(admin);
        pcsDaoUpserts();

        enclaveIdDao.grantRoles(admin, enclaveIdDao.ATTESTER_ROLE());
        fmspcTcbDao.grantRoles(admin, fmspcTcbDao.ATTESTER_ROLE());

        qeIdDaoUpsert(4, "/forge-test/assets/0625/qe_td.json");
        fmspcTcbDaoUpsert("/forge-test/assets/0625/tcbinfov3_00806f050000.json");
        vm.stopPrank();
    }

    function testGetCollateralVersions() public view {
        uint32 tcbEval = fmspcTcbDao.TCB_EVALUATION_NUMBER();

        assertEq(pccsRouter.getPcsCollateralVersion(CA.ROOT, false), 1);
        assertEq(pccsRouter.getPcsCollateralVersion(CA.ROOT, true), 1);
        assertEq(pccsRouter.getPcsCollateralVersion(CA.PLATFORM, false), 1);
        assertEq(pccsRouter.getQeIdentityVersion(EnclaveId.TD_QE, 4, tcbEval), 1);
        assertEq(pccsRouter.getFmspcTcbVersion(TcbId.TDX, bytes6(uint48(0x00806f050000)), 3, tcbEval), 1);
    }

    function testHasCollateralChanged() public view {
        uint32 tcbEval = fmspcTcbDao.TCB_EVALUATION_NUMBER();
        (bool rootCertChanged, uint256 rootCertVersion) = pccsRouter.hasPcsCollateralChanged(CA.ROOT, false, 0);
        (bool rootCertChangedFromCurrent, uint256 rootCertCurrentVersion) =
            pccsRouter.hasPcsCollateralChanged(CA.ROOT, false, 1);
        (bool qeChanged, uint256 qeVersion) = pccsRouter.hasQeIdentityChanged(EnclaveId.TD_QE, 4, tcbEval, 0);
        (bool qeChangedFromCurrent, uint256 qeCurrentVersion) =
            pccsRouter.hasQeIdentityChanged(EnclaveId.TD_QE, 4, tcbEval, 1);
        (bool tcbChanged, uint256 tcbVersion) =
            pccsRouter.hasFmspcTcbChanged(TcbId.TDX, bytes6(uint48(0x00806f050000)), 3, tcbEval, 0);
        (bool tcbChangedFromCurrent, uint256 tcbCurrentVersion) =
            pccsRouter.hasFmspcTcbChanged(TcbId.TDX, bytes6(uint48(0x00806f050000)), 3, tcbEval, 1);

        assertTrue(rootCertChanged);
        assertEq(rootCertVersion, 1);
        assertFalse(rootCertChangedFromCurrent);
        assertEq(rootCertCurrentVersion, 1);

        assertTrue(qeChanged);
        assertEq(qeVersion, 1);
        assertFalse(qeChangedFromCurrent);
        assertEq(qeCurrentVersion, 1);

        assertTrue(tcbChanged);
        assertEq(tcbVersion, 1);
        assertFalse(tcbChangedFromCurrent);
        assertEq(tcbCurrentVersion, 1);
    }

    function testNewVersionApisRespectCallerRestriction() public {
        uint32 tcbEval = fmspcTcbDao.TCB_EVALUATION_NUMBER();

        vm.prank(admin);
        pccsRouter.enableCallerRestriction();

        vm.expectRevert(PCCSRouter.Forbidden.selector);
        pccsRouter.getQeIdentityVersion(EnclaveId.TD_QE, 4, tcbEval);

        vm.prank(admin);
        pccsRouter.setAuthorized(address(this), true);

        assertEq(pccsRouter.getQeIdentityVersion(EnclaveId.TD_QE, 4, tcbEval), 1);
        assertEq(pccsRouter.getFmspcTcbVersion(TcbId.TDX, FMSPC_TDX, 3, tcbEval), 1);
        assertEq(pccsRouter.getPcsCollateralVersion(CA.ROOT, false), 1);
    }

    function testNewVersionApisRevertWhenVersionedDaoNotConfigured() public {
        uint32 unsetEval = 9999;

        vm.expectRevert(
            abi.encodeWithSelector(PCCSRouter.QEIdentityExpiredOrNotFound.selector, EnclaveId.TD_QE, uint256(4))
        );
        pccsRouter.getQeIdentityVersion(EnclaveId.TD_QE, 4, unsetEval);

        vm.expectRevert(abi.encodeWithSelector(PCCSRouter.FmspcTcbExpiredOrNotFound.selector, TcbId.TDX, uint256(3)));
        pccsRouter.getFmspcTcbVersion(TcbId.TDX, FMSPC_TDX, 3, unsetEval);

        vm.expectRevert(
            abi.encodeWithSelector(PCCSRouter.QEIdentityExpiredOrNotFound.selector, EnclaveId.TD_QE, uint256(4))
        );
        pccsRouter.hasQeIdentityChanged(EnclaveId.TD_QE, 4, unsetEval, 0);

        vm.expectRevert(abi.encodeWithSelector(PCCSRouter.FmspcTcbExpiredOrNotFound.selector, TcbId.TDX, uint256(3)));
        pccsRouter.hasFmspcTcbChanged(TcbId.TDX, FMSPC_TDX, 3, unsetEval, 0);
    }

    function testVersionIncrementsOnSecondValidUpsertForAllCollateralTypes() public {
        uint32 tcbEval = fmspcTcbDao.TCB_EVALUATION_NUMBER();

        // PCS CRL versioning: insert 0825 CRL while it is valid, then replace with newer 1025 CRL.
        vm.warp(1755302400); // 2025-08-16T00:00:00Z
        vm.startPrank(admin);
        bytes memory oldPlatformCrl = vm.readFileBinary(string.concat(vm.projectRoot(), "/forge-test/assets/0825/platform_crl.der"));
        pcsDao.upsertPckCrl(CA.PLATFORM, oldPlatformCrl);
        assertEq(pccsRouter.getPcsCollateralVersion(CA.PLATFORM, true), 1);

        // QE Identity and TCB fixtures in setUp are from 0625; replace with newer 1025 fixtures.
        vm.warp(1761004800); // 2025-10-21T00:00:00Z
        qeIdDaoUpsert(4, "/forge-test/assets/1025/identity.json");
        fmspcTcbDaoUpsert("/forge-test/assets/1025/tcb_info.json");

        bytes memory newPlatformCrl = vm.readFileBinary(string.concat(vm.projectRoot(), "/forge-test/assets/1025/pck_crl.der"));
        pcsDao.upsertPckCrl(CA.PLATFORM, newPlatformCrl);
        vm.stopPrank();

        assertEq(pccsRouter.getQeIdentityVersion(EnclaveId.TD_QE, 4, tcbEval), 2);
        assertEq(pccsRouter.getFmspcTcbVersion(TcbId.TDX, FMSPC_TDX, 3, tcbEval), 2);
        assertEq(pccsRouter.getPcsCollateralVersion(CA.PLATFORM, true), 2);
    }

    function testE2EHasChangedFlipsAfterRealCollateralUpdate() public {
        uint32 tcbEval = fmspcTcbDao.TCB_EVALUATION_NUMBER();

        // No updates since setUp baseline insertions.
        (bool qeChangedBefore, uint256 qeVersionBefore) = pccsRouter.hasQeIdentityChanged(EnclaveId.TD_QE, 4, tcbEval, 1);
        (bool tcbChangedBefore, uint256 tcbVersionBefore) =
            pccsRouter.hasFmspcTcbChanged(TcbId.TDX, FMSPC_TDX, 3, tcbEval, 1);
        assertFalse(qeChangedBefore);
        assertEq(qeVersionBefore, 1);
        assertFalse(tcbChangedBefore);
        assertEq(tcbVersionBefore, 1);

        vm.warp(1761004800); // 2025-10-21T00:00:00Z
        vm.startPrank(admin);
        qeIdDaoUpsert(4, "/forge-test/assets/1025/identity.json");
        fmspcTcbDaoUpsert("/forge-test/assets/1025/tcb_info.json");
        vm.stopPrank();

        (bool qeChangedAfter, uint256 qeVersionAfter) = pccsRouter.hasQeIdentityChanged(EnclaveId.TD_QE, 4, tcbEval, 1);
        (bool tcbChangedAfter, uint256 tcbVersionAfter) =
            pccsRouter.hasFmspcTcbChanged(TcbId.TDX, FMSPC_TDX, 3, tcbEval, 1);
        assertTrue(qeChangedAfter);
        assertEq(qeVersionAfter, 2);
        assertTrue(tcbChangedAfter);
        assertEq(tcbVersionAfter, 2);
    }
}
