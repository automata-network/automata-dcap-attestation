// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../contracts/verifiers/V5QuoteVerifier.sol";

/// Pure TCB tests: synthetic levels do not stand in for signed collateral or proofs.
contract TdxStatusV2Harness is V5QuoteVerifier {
    constructor() V5QuoteVerifier(address(0), address(0)) {}

    function status(bytes calldata body, PCKCertTCB memory pck, TdxTcbData memory data, bool v2)
        external
        pure
        returns (bool, string memory, uint8, uint256)
    {
        return _verifyTdxBody(body, pck, EnclaveIdTcbStatus.OK, data, v2);
    }
}

contract TdxStatusV2Test is Test {
    TdxStatusV2Harness harness = new TdxStatusV2Harness();

    function fixture(TCBStatus preliminary, TCBStatus complete, TCBStatus moduleStatus)
        internal
        pure
        returns (bytes memory body, PCKCertTCB memory pck, V5QuoteVerifier.TdxTcbData memory data)
    {
        body = new bytes(648);
        // SVN 1, module 1; after a TD-preserving update SVN2 is 2, module 1.
        body[0] = 0x01;
        body[1] = 0x01;
        body[584] = 0x02;
        body[585] = 0x01;
        body[123] = 0x10;
        pck.cpusvns = new uint8[](16);
        data.levels = new TCBLevelsObj[](2);
        for (uint256 i; i < 2; ++i) {
            data.levels[i].sgxComponentCpuSvns = new uint8[](16);
            data.levels[i].tdxComponentCpuSvns = new uint8[](16);
            data.levels[i].tdxComponentCpuSvns[0] = uint8(2 - i);
            data.levels[i].tdxComponentCpuSvns[1] = 1;
            data.levels[i].status = i == 0 ? preliminary : complete;
        }
        data.module.mrsigner = new bytes(48);
        data.identities = new TDXModuleIdentity[](1);
        data.identities[0].id = "TDX_01";
        data.identities[0].mrsigner = new bytes(48);
        data.identities[0].tcbLevels = new TDXModuleTCBLevelsObj[](1);
        data.identities[0].tcbLevels[0].isvsvn = 1;
        data.identities[0].tcbLevels[0].status = moduleStatus;
    }

    function testRelaunchPreservesFirstPartialMatchAndStatusEightNine() public {
        for (uint8 configuration; configuration < 2; ++configuration) {
            (bytes memory body, PCKCertTCB memory pck, V5QuoteVerifier.TdxTcbData memory data) = fixture(
                configuration == 0 ? TCBStatus.OK : TCBStatus.TCB_CONFIGURATION_NEEDED,
                TCBStatus.TCB_OUT_OF_DATE,
                TCBStatus.TCB_OUT_OF_DATE
            );
            (bool success,, uint8 status, uint256 selected) = harness.status(body, pck, data, true);
            assertTrue(success);
            assertEq(status, 8 + configuration);
            assertEq(selected, 1);
            (success,, status,) = harness.status(body, pck, data, false);
            assertTrue(success);
            assertEq(status, 4, "legacy status is intentionally unchanged");
        }
    }

    function testModuleDowngradeAloneIsNotRelaunch() public {
        (bytes memory body, PCKCertTCB memory pck, V5QuoteVerifier.TdxTcbData memory data) =
            fixture(TCBStatus.OK, TCBStatus.OK, TCBStatus.TCB_OUT_OF_DATE);
        (bool success,, uint8 status,) = harness.status(body, pck, data, true);
        assertTrue(success);
        assertEq(status, 4, "relaunch tests the raw platform status, not module-converged status");
    }

    function testProductionUsesCompleteTdxStatusNotRevokedPartialMatch() public {
        (bytes memory body, PCKCertTCB memory pck, V5QuoteVerifier.TdxTcbData memory data) =
            fixture(TCBStatus.TCB_REVOKED, TCBStatus.TCB_OUT_OF_DATE, TCBStatus.TCB_OUT_OF_DATE);
        (bool success,, uint8 status,) = harness.status(body, pck, data, true);
        assertTrue(success);
        assertEq(status, 4, "revoked partial status cannot trigger relaunch");
        (success,,,) = harness.status(body, pck, data, false);
        assertFalse(success, "legacy rejects the revoked partial match");
        data.levels[1].status = TCBStatus.TCB_REVOKED;
        (success,,,) = harness.status(body, pck, data, true);
        assertFalse(success, "V2 rejects a revoked complete match");
    }

    function testV2ChecksTdxZeroModuleIdentity() public {
        (bytes memory body, PCKCertTCB memory pck, V5QuoteVerifier.TdxTcbData memory data) =
            fixture(TCBStatus.OK, TCBStatus.OK, TCBStatus.TCB_REVOKED);
        body[1] = 0;
        data.levels[0].tdxComponentCpuSvns[1] = 0;
        data.levels[1].tdxComponentCpuSvns[1] = 0;
        data.identities[0].id = "TDX_00";
        (bool success,,,) = harness.status(body, pck, data, true);
        assertFalse(success);
        (success,,,) = harness.status(body, pck, data, false);
        assertTrue(success, "legacy base module bypass remains unchanged");
    }
}
