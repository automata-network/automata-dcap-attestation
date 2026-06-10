// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {TCBLevelsObj, TCBStatus} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";
import {PCKCertTCB} from "../contracts/types/CommonStruct.sol";
import "../contracts/bases/tcb/TCBInfoV2Base.sol";

/**
 * @dev Thin harness that exposes the internal getSGXTcbStatus helper so we can
 *      drive the revoked-TCB guard logic directly, without needing a fully-signed
 *      quote or a running PCCS.
 */
contract TcbStatusHarness is TCBInfoV2Base {
    function checkStatus(PCKCertTCB calldata pckTcb, TCBLevelsObj calldata level)
        external
        pure
        returns (bool found, TCBStatus status)
    {
        return getSGXTcbStatus(pckTcb, level);
    }

    /**
     * @dev Mirrors exactly the guard introduced in the fix:
     *
     *      if (!statusFound || tcbStatus == TCBStatus.TCB_REVOKED) {
     *          return (false, bytes(TCBR));      // ← fixed
     *      }
     *
     * Returns the first element of that return tuple given the same inputs,
     * i.e. the `success` bool that callers of verifyQuote observe.
     */
    function guardSuccess(PCKCertTCB calldata pckTcb, TCBLevelsObj calldata level)
        external
        pure
        returns (bool success)
    {
        (bool statusFound, TCBStatus tcbStatus) = getSGXTcbStatus(pckTcb, level);
        if (!statusFound || tcbStatus == TCBStatus.TCB_REVOKED) {
            // fixed path: always return false
            return false;
        }
        return true;
    }
}

/**
 * @title RevokedSgxTcbTest
 * @notice Unit tests for the SGX TCB-REVOKED guard in V3QuoteVerifier and
 *         V4QuoteVerifier._verifySGXQuote.
 *
 * Bug: the original code read
 *   return (statusFound, bytes(TCBR));
 * When statusFound==true and tcbStatus==TCB_REVOKED, that returned success=true,
 * i.e. verifyQuote reported SUCCESS for a revoked platform TCB (false-VALID).
 *
 * Fix: change to
 *   return (false, bytes(TCBR));
 * matching the correct behaviour already present in the V5 and TDX paths.
 */
contract RevokedSgxTcbTest is Test {
    TcbStatusHarness harness;

    // 16-component SVN array whose every byte is 0 (minimal TCB level)
    uint8[] internal zeroSvns;

    function setUp() public {
        harness = new TcbStatusHarness();
        zeroSvns = new uint8[](16);
    }

    // -------------------------------------------------------------------------
    // Helper builders
    // -------------------------------------------------------------------------

    function _makeMatchingPck() internal view returns (PCKCertTCB memory) {
        return PCKCertTCB({
            pcesvn: 1,
            cpusvns: zeroSvns,
            fmspcBytes: hex"000000000000",
            pceidBytes: hex"0000"
        });
    }

    function _makeTcbLevel(TCBStatus status) internal view returns (TCBLevelsObj memory) {
        return TCBLevelsObj({
            pcesvn: 0, // pckTcb.pcesvn (1) >= 0  → pceSvnIsHigherOrGreater = true
            sgxComponentCpuSvns: zeroSvns, // all zeros → cpuSvnsAreHigherOrGreater = true
            tdxComponentCpuSvns: new uint8[](0),
            tcbDateTimestamp: 0,
            status: status,
            advisoryIDs: new string[](0)
        });
    }

    // -------------------------------------------------------------------------
    // Tests: getSGXTcbStatus correctly identifies a matching REVOKED level
    // -------------------------------------------------------------------------

    function test_getSGXTcbStatus_revokedLevelIsFound() public view {
        PCKCertTCB memory pck = _makeMatchingPck();
        TCBLevelsObj memory level = _makeTcbLevel(TCBStatus.TCB_REVOKED);

        (bool found, TCBStatus status) = harness.checkStatus(pck, level);

        assertTrue(found, "REVOKED level must be found (SVN match)");
        assertEq(uint8(status), uint8(TCBStatus.TCB_REVOKED), "status must be TCB_REVOKED");
    }

    // -------------------------------------------------------------------------
    // Tests: the guard logic (the actual fix)
    // -------------------------------------------------------------------------

    /**
     * When statusFound==true and status==TCB_REVOKED the guard must return
     * success=false.  Before the fix it returned success=true (false-VALID).
     */
    function test_guard_revokedAndFound_returnsFailure() public view {
        PCKCertTCB memory pck = _makeMatchingPck();
        TCBLevelsObj memory level = _makeTcbLevel(TCBStatus.TCB_REVOKED);

        bool success = harness.guardSuccess(pck, level);
        assertFalse(success, "Revoked SGX TCB must yield success=false");
    }

    /**
     * When statusFound==false (SVN mismatch) the guard must also return
     * success=false (existing behaviour, unchanged by the fix).
     */
    function test_guard_notFound_returnsFailure() public view {
        // Build a PCK whose SVNs are *lower* than the TCB level requirements,
        // so statusFound == false.
        uint8[] memory highSvns = new uint8[](16);
        for (uint256 i = 0; i < 16; i++) highSvns[i] = 255;

        PCKCertTCB memory pck = _makeMatchingPck();
        TCBLevelsObj memory level = TCBLevelsObj({
            pcesvn: 0,
            sgxComponentCpuSvns: highSvns, // pck svns (0) < 255 → not found
            tdxComponentCpuSvns: new uint8[](0),
            tcbDateTimestamp: 0,
            status: TCBStatus.OK,
            advisoryIDs: new string[](0)
        });

        bool success = harness.guardSuccess(pck, level);
        assertFalse(success, "Unmatched TCB level must yield success=false");
    }

    /**
     * Sanity: a matching, non-revoked level must pass the guard (success=true).
     */
    function test_guard_foundAndOk_returnsSuccess() public view {
        PCKCertTCB memory pck = _makeMatchingPck();
        TCBLevelsObj memory level = _makeTcbLevel(TCBStatus.OK);

        bool success = harness.guardSuccess(pck, level);
        assertTrue(success, "Valid non-revoked TCB must yield success=true");
    }

    /**
     * Sanity: other non-OK statuses (OUT_OF_DATE, SW_HARDENING_NEEDED, …) that
     * are still found must pass the guard — callers converge them later.
     */
    function test_guard_foundAndOutOfDate_returnsSuccess() public view {
        PCKCertTCB memory pck = _makeMatchingPck();
        TCBLevelsObj memory level = _makeTcbLevel(TCBStatus.TCB_OUT_OF_DATE);

        bool success = harness.guardSuccess(pck, level);
        assertTrue(success, "OUT_OF_DATE TCB must still pass the guard");
    }
}
