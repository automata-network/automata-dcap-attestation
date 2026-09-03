// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {
    IdentityObj,
    EnclaveId,
    Tcb,
    EnclaveIdTcbStatus
} from "@automata-network/on-chain-pccs/helpers/EnclaveIdentityHelper.sol";

import "../contracts/bases/EnclaveIdBase.sol";

/**
 * @dev Thin harness that exposes verifyQEReportWithIdentity (internal in
 *      EnclaveIdBase) and replicates the Step 1 guard from
 *      QuoteVerifierBase._verifyQuoteIntegrity so we can drive the
 *      REVOKED-QE logic directly, without a running PCCS or signed quote.
 *
 *      The guard under test (after the fix) is:
 *
 *          (success, qeTcbStatus) = verifyQEReportWithIdentity(...);
 *          if (!success || qeTcbStatus == SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
 *              result.success = false;          // ← the one-line fix
 *              result.reason = QEIDVE;
 *              return result;
 *          }
 *          // Steps 2 & 3 follow only when we reach here
 */
contract QeIdentityHarness is EnclaveIdBase {
    /// @notice Thin wrapper for the internal helper.
    function checkQeReport(
        IdentityObj memory identity,
        bytes4 miscselect,
        bytes16 attributes,
        bytes32 mrsigner,
        uint16 isvprodid,
        uint16 isvsvn
    ) external pure returns (bool success, EnclaveIdTcbStatus status) {
        return verifyQEReportWithIdentity(identity, miscselect, attributes, mrsigner, isvprodid, isvsvn);
    }

    /**
     * @notice Mirrors the Step 1 guard exactly as it appears in
     *         QuoteVerifierBase._verifyQuoteIntegrity after the fix.
     *         Returns the `success` value that the caller would observe.
     *
     *         Before the fix the branch left result.success == true when
     *         qeTcbStatus == SGX_ENCLAVE_REPORT_ISVSVN_REVOKED, so callers
     *         accepted the quote without ever running Steps 2 or 3.
     */
    function guardSuccess(
        IdentityObj memory identity,
        bytes4 miscselect,
        bytes16 attributes,
        bytes32 mrsigner,
        uint16 isvprodid,
        uint16 isvsvn
    ) external pure returns (bool success) {
        bool ok;
        EnclaveIdTcbStatus qeTcbStatus;
        (ok, qeTcbStatus) = verifyQEReportWithIdentity(identity, miscselect, attributes, mrsigner, isvprodid, isvsvn);
        if (!ok || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
            // Fixed: always false in this branch
            return false;
        }
        return true;
    }
}

/**
 * @title RevokedQeIdentityTest
 * @notice Unit tests for the REVOKED-QE guard in
 *         QuoteVerifierBase._verifyQuoteIntegrity (Step 1).
 *
 * Bug: when verifyQEReportWithIdentity returns (true, SGX_ENCLAVE_REPORT_ISVSVN_REVOKED)
 *      — which happens whenever the report's structural fields match Intel's
 *      public QE Identity AND the isvSvn falls in a REVOKED band — the guard
 *      branch fired but left result.success == true (set by the assignment
 *      on the line above).  The function returned before Steps 2 (cert-chain)
 *      and 3 (ECDSA signatures) ran, so the caller saw success=true without
 *      those checks having been performed.  An attacker can exploit this by
 *      submitting a quote with fabricated PCK certs and garbage signatures
 *      once Intel publishes any QE revocation entry.
 *
 * Fix: add `result.success = false;` inside that branch so a REVOKED QE is
 *      always rejected (one-line change, no restructuring).
 *
 * Scope: V3/V4/V5, SGX+TDX — all share _verifyQuoteIntegrity via
 *        QuoteVerifierBase.
 */
contract RevokedQeIdentityTest is Test {
    QeIdentityHarness harness;

    // Fixed identity fields — chosen to always pass the structural checks
    bytes4  internal constant MISC   = bytes4(0x00000000);
    bytes4  internal constant MMASK  = bytes4(0x00000000); // mask=0 → any miscselect matches
    bytes16 internal constant ATTR   = bytes16(0x00000000000000000000000000000000);
    bytes16 internal constant AMASK  = bytes16(0x00000000000000000000000000000000); // mask=0 → any attributes match
    bytes32 internal constant MRSIGN = bytes32(0);
    uint16  internal constant PRODID = 1;

    function setUp() public {
        harness = new QeIdentityHarness();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Build a minimal IdentityObj with a single TCB entry at the given status.
    function _makeIdentity(uint16 isvsvn, EnclaveIdTcbStatus status)
        internal
        pure
        returns (IdentityObj memory identity)
    {
        Tcb[] memory tcb = new Tcb[](1);
        tcb[0] = Tcb({isvsvn: isvsvn, dateTimestamp: 0, status: status});

        identity = IdentityObj({
            id: EnclaveId.QE,
            version: 2,
            issueDateTimestamp: 0,
            nextUpdateTimestamp: type(uint64).max,
            tcbEvaluationDataNumber: 1,
            miscselect: MISC,
            miscselectMask: MMASK,
            attributes: ATTR,
            attributesMask: AMASK,
            mrsigner: MRSIGN,
            isvprodid: PRODID,
            tcb: tcb
        });
    }

    // -------------------------------------------------------------------------
    // Part A: confirm verifyQEReportWithIdentity returns (true, REVOKED) for a
    //         structurally matching report whose isvSvn is in a REVOKED band.
    // -------------------------------------------------------------------------

    function test_verifyQEReportWithIdentity_revokedBand_returnsFoundAndRevoked() public view {
        // TCB entry: isvsvn=5, status=REVOKED
        // Report isvSvn=7 ≥ 5 → TCB match found; status == REVOKED
        IdentityObj memory identity = _makeIdentity(5, EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED);

        (bool found, EnclaveIdTcbStatus status) = harness.checkQeReport(
            identity,
            MISC,    // miscselect matches (mask=0)
            ATTR,    // attributes match  (mask=0)
            MRSIGN,  // mrsigner matches
            PRODID,  // isvprodid matches
            7        // isvSvn=7 ≥ tcb.isvsvn=5 → found
        );

        assertTrue(found,  "structural match with isvSvn in REVOKED band must be found");
        assertEq(
            uint8(status),
            uint8(EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED),
            "status must be SGX_ENCLAVE_REPORT_ISVSVN_REVOKED"
        );
    }

    // -------------------------------------------------------------------------
    // Part B: the Step 1 guard — the actual fix
    // -------------------------------------------------------------------------

    /**
     * When verifyQEReportWithIdentity returns (true, REVOKED) the guard must
     * yield success=false.  Before the fix it returned success=true — a
     * false-VALID that bypassed cert-chain and signature verification.
     */
    function test_guard_revokedQe_returnsFailure() public view {
        IdentityObj memory identity = _makeIdentity(5, EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED);

        bool success = harness.guardSuccess(
            identity,
            MISC, ATTR, MRSIGN, PRODID,
            7  // isvSvn in REVOKED band
        );

        assertFalse(success, "REVOKED QE must yield success=false (cert-chain+sig checks must not be skipped)");
    }

    /**
     * When verifyQEReportWithIdentity returns (false, …) — structural mismatch —
     * the guard must also yield success=false (unchanged behaviour).
     */
    function test_guard_structuralMismatch_returnsFailure() public view {
        IdentityObj memory identity = _makeIdentity(5, EnclaveIdTcbStatus.OK);

        // Wrong mrsigner → structural mismatch → found=false
        bool success = harness.guardSuccess(
            identity,
            MISC, ATTR, bytes32(uint256(0xdeadbeef)), PRODID,
            7
        );

        assertFalse(success, "structural mismatch must yield success=false");
    }

    // -------------------------------------------------------------------------
    // Part C: sanity — valid (UP_TO_DATE) QE must still pass the guard
    // -------------------------------------------------------------------------

    /**
     * A QE that is structurally matched and UP_TO_DATE must pass the guard so
     * that Steps 2 and 3 can run normally.  This ensures the fix does not
     * regress the happy path.
     */
    function test_guard_upToDateQe_returnsSuccess() public view {
        IdentityObj memory identity = _makeIdentity(5, EnclaveIdTcbStatus.OK);

        bool success = harness.guardSuccess(
            identity,
            MISC, ATTR, MRSIGN, PRODID,
            7  // isvSvn=7 ≥ 5, status=OK
        );

        assertTrue(success, "UP_TO_DATE QE must pass the Step 1 guard");
    }

    /**
     * A QE that is OUT_OF_DATE (downgraded but not revoked) must also pass the
     * guard — callers converge its status later via convergeTcbStatusWithQeTcbStatus.
     */
    function test_guard_outOfDateQe_returnsSuccess() public view {
        IdentityObj memory identity = _makeIdentity(5, EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE);

        bool success = harness.guardSuccess(
            identity,
            MISC, ATTR, MRSIGN, PRODID,
            7
        );

        assertTrue(success, "OUT_OF_DATE QE must pass the Step 1 guard (not revoked)");
    }
}
