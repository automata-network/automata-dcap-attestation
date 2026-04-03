// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./utils/PCCSSetupBase.sol";

import {CA} from "@automata-network/on-chain-pccs/Common.sol";
import {EnclaveId} from "@automata-network/on-chain-pccs/helpers/EnclaveIdentityHelper.sol";
import {TcbId} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";

contract PCCSRouterVersioningTest is PCCSSetupBase {
    PCCSRouter pccsRouter;

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
}
