// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../pcs/PCSSetupBase.t.sol";

import {TCBConstants} from "./TCBConstants.t.sol";

contract AutomataFmspcTcbDaoTest is PCSSetupBase, TCBConstants {
    function setUp() public override {
        super.setUp();
    }

    function testAttestFmspcTcbSgxV2() public {
        uint8 tcbType = 0;
        string memory fmspcStr = "00606a000000";
        bytes6 fmspcBytes = hex"00606a000000";
        uint32 version = 2;

        TcbInfoJsonObj memory tcbInfoObj =
            TcbInfoJsonObj({tcbInfoStr: string(sgx_v2_tcbStr), signature: sgx_v2_signature});

        bytes32 attestationId = fmspcTcbDao.upsertFmspcTcb(tcbInfoObj);
        assertEq(pccsStorage.collateralPointer(fmspcTcbDao.FMSPC_TCB_KEY(tcbType, fmspcBytes, version)), attestationId);

        vm.startPrank(admin);
        TcbInfoJsonObj memory fetched = fmspcTcbDao.getTcbInfo(tcbType, fmspcStr, version);
        assertEq(fetched.signature, tcbInfoObj.signature);
        assertEq(
            fmspcTcbDao.getCollateralHash(fmspcTcbDao.FMSPC_TCB_KEY(tcbType, fmspcBytes, version)),
            sha256(bytes(tcbInfoObj.tcbInfoStr))
        );
        vm.stopPrank();
    }

    function testAttestFmspcTcbSgxV3() public {
        // July 4th, 2024, 2:22:34 AM UTC
        vm.warp(1720059754);

        uint8 tcbType = 0;
        string memory fmspcStr = "10A06D070000";
        bytes6 fmspcBytes = hex"10A06D070000";
        uint32 version = 3;

        TcbInfoJsonObj memory tcbInfoObj =
            TcbInfoJsonObj({tcbInfoStr: string(sgx_v3_tcbStr), signature: sgx_v3_signature});

        bytes32 attestationId = fmspcTcbDao.upsertFmspcTcb(tcbInfoObj);
        assertEq(pccsStorage.collateralPointer(fmspcTcbDao.FMSPC_TCB_KEY(tcbType, fmspcBytes, version)), attestationId);

        vm.startPrank(admin);
        TcbInfoJsonObj memory fetched = fmspcTcbDao.getTcbInfo(tcbType, fmspcStr, version);
        assertEq(fetched.signature, tcbInfoObj.signature);
        assertEq(
            fmspcTcbDao.getCollateralHash(fmspcTcbDao.FMSPC_TCB_KEY(tcbType, fmspcBytes, version)),
            sha256(bytes(tcbInfoObj.tcbInfoStr))
        );
        vm.stopPrank();
    }

    function testAttestFmspcTcbTdxV3() public {
        vm.warp(1715843418);

        uint8 tcbType = 1;
        string memory fmspcStr = "90c06f000000";
        bytes6 fmspcBytes = hex"90c06f000000";
        uint32 version = 3;

        TcbInfoJsonObj memory tcbInfoObj = TcbInfoJsonObj({tcbInfoStr: string(tdx_tcbStr), signature: tdx_signature});

        bytes32 attestationId = fmspcTcbDao.upsertFmspcTcb(tcbInfoObj);
        assertEq(pccsStorage.collateralPointer(fmspcTcbDao.FMSPC_TCB_KEY(tcbType, fmspcBytes, version)), attestationId);

        vm.startPrank(admin);
        TcbInfoJsonObj memory fetched = fmspcTcbDao.getTcbInfo(tcbType, fmspcStr, version);
        assertEq(fetched.signature, tcbInfoObj.signature);
        assertEq(
            fmspcTcbDao.getCollateralHash(fmspcTcbDao.FMSPC_TCB_KEY(tcbType, fmspcBytes, version)),
            sha256(bytes(tcbInfoObj.tcbInfoStr))
        );
        vm.stopPrank();
    }

    function testTcbIssuerChain() public readAsAuthorizedCaller {
        (bytes memory fetchedSigning, bytes memory fetchedRoot) = fmspcTcbDao.getTcbIssuerChain();
        assertEq(keccak256(signingDer), keccak256(fetchedSigning));
        assertEq(keccak256(rootDer), keccak256(fetchedRoot));
    }
}
