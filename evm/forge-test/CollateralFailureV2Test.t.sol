// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "./QuoteV3V4V2Test.t.sol";
import "../contracts/verifiers/V5QuoteVerifier.sol";

contract CollateralFailureV2Test is QuoteV3V4V2Test {
    function legacyFor(IQuoteVerifier verifier) internal returns (AutomataDcapAttestationFee legacy) {
        vm.startPrank(admin);
        legacy = new AutomataDcapAttestationFee(admin);
        legacy.setQuoteVerifier(address(verifier));
        vm.stopPrank();
    }
    function feeFor(IQuoteVerifier verifier) internal returns (AutomataDcapAttestationV2 fee) {
        vm.startPrank(admin);
        fee = new AutomataDcapAttestationV2(admin);
        fee.setQuoteVerifier(address(verifier));
        pccsRouter.setAuthorized(address(fee), true);
        pccsRouter.setAuthorized(address(verifier), true);
        vm.stopPrank();
    }

    function testV2RejectsAbsentIdentityThroughStrictRouterGetter() public {
        testQuoteV3OnChainAttestation();
        AutomataDcapAttestationV2 fee = feeFor(attestation.quoteVerifiers(3));
        // Also defend against routers returning a zero hash instead of reverting.
        vm.mockCall(
            address(pccsRouter),
            abi.encodeWithSelector(IPCCSRouter.getQeIdentityContentHash.selector, EnclaveId.QE, uint256(4), uint32(17)),
            abi.encode(bytes32(0))
        );
        (bool success, bytes memory output,) = fee.verifyAndAttestOnChainV2(readHex("quote-v3"), 17, false);
        assertFalse(success);
        assertEq(string(output), QEIDCH);
        // The legacy verifier does not acquire this new strict hash dependency.
        (success,) = legacyFor(attestation.quoteVerifiers(3)).verifyAndAttestOnChain(readHex("quote-v3"), 17);
        assertTrue(success);
    }

    function testV2ExpiredIdentityHasExplicitRouterFailure() public {
        testQuoteV3OnChainAttestation();
        AutomataDcapAttestationV2 fee = feeFor(attestation.quoteVerifiers(3));
        vm.startPrank(admin);
        pccsRouter.setAuthorized(address(this), true);
        vm.stopPrank();
        IdentityObj memory identity = pccsRouter.getQeIdentity(EnclaveId.QE, 4, 17);
        vm.warp(identity.nextUpdateTimestamp + 1);
        // Preserve the router's legacy empty-object behavior, but not on the V2 path.
        assertEq(pccsRouter.getQeIdentity(EnclaveId.QE, 4, 17).tcb.length, 0);
        bytes memory raw = readHex("quote-v3");
        vm.expectRevert(abi.encodeWithSelector(PCCSRouter.QEIdentityExpiredOrNotFound.selector, EnclaveId.QE, 4));
        fee.verifyAndAttestOnChainV2(raw, 17, false);
    }

    function testV2MissingIdentityHasExplicitRouterFailure() public {
        testQuoteV3OnChainAttestation();
        AutomataDcapAttestationV2 fee = feeFor(attestation.quoteVerifiers(3));
        // Missing DAO data is represented by zero validity timestamps.
        vm.mockCall(address(enclaveIdDao), abi.encodeWithSelector(bytes4(0x3e960426)),
            abi.encode(uint64(0), uint64(0)));
        bytes memory raw = readHex("quote-v3");
        vm.expectRevert(abi.encodeWithSelector(PCCSRouter.QEIdentityExpiredOrNotFound.selector, EnclaveId.QE, 4));
        fee.verifyAndAttestOnChainV2(raw, 17, false);
        (bool success, bytes memory output) = legacyFor(attestation.quoteVerifiers(3)).verifyAndAttestOnChain(raw, 17);
        assertFalse(success);
        assertEq(string(output), QEIDVE);
    }

    function testV5SgxMissingLevelReturnsFailureInsteadOfPanic() public {
        testQuoteV3OnChainAttestation();
        // Synthetic V5 SGX framing reuses a valid PCK chain/QE report. Only the
        // quote-signature verification is mocked: this is a TCB branch regression,
        // not evidence of an authenticated V5 success or a real ZK proof.
        bytes memory v3 = readHex("quote-v3");
        bytes memory header = BytesUtils.substring(v3, 0, 48);
        header[0] = 0x05;
        bytes memory auth = BytesUtils.substring(v3, 436, v3.length - 436);
        bytes memory nested = abi.encodePacked(
            BytesUtils.substring(auth, 0, 128), hex"0600", le32(uint32(auth.length - 128)),
            BytesUtils.substring(auth, 128, auth.length - 128)
        );
        bytes memory raw = abi.encodePacked(header, hex"010080010000", BytesUtils.substring(v3, 48, 384),
            le32(uint32(nested.length)), nested);
        V5QuoteVerifier verifier = new V5QuoteVerifier(P256_VERIFIER, address(pccsRouter));
        AutomataDcapAttestationV2 fee = feeFor(verifier);
        vm.mockCall(P256_VERIFIER, bytes(""), abi.encode(uint256(1)));
        TCBLevelsObj[] memory levels = new TCBLevelsObj[](0);
        TDXModule memory module;
        TDXModuleIdentity[] memory identities = new TDXModuleIdentity[](0);
        vm.mockCall(address(pccsRouter), abi.encodeWithSelector(IPCCSRouter.getFmspcTcbV3.selector),
            abi.encode(levels, module, identities));
        (bool success, bytes memory output,) = fee.verifyAndAttestOnChainV2(raw, 17, false);
        assertFalse(success);
        assertEq(string(output), TCBR);
        AutomataDcapAttestationFee legacy = legacyFor(verifier);
        vm.expectRevert(stdError.indexOOBError);
        legacy.verifyAndAttestOnChain(raw, 17);
        // A nonempty list with no matching SVN must take the same failure branch.
        levels = new TCBLevelsObj[](1);
        levels[0].sgxComponentCpuSvns = new uint8[](16);
        levels[0].sgxComponentCpuSvns[0] = 255;
        vm.mockCall(address(pccsRouter), abi.encodeWithSelector(IPCCSRouter.getFmspcTcbV3.selector),
            abi.encode(levels, module, identities));
        (success, output,) = fee.verifyAndAttestOnChainV2(raw, 17, false);
        assertFalse(success);
        assertEq(string(output), TCBR);
        levels[0].sgxComponentCpuSvns[0] = 0;
        levels[0].status = TCBStatus.OK;
        vm.mockCall(address(pccsRouter), abi.encodeWithSelector(IPCCSRouter.getFmspcTcbV3.selector),
            abi.encode(levels, module, identities));
        (success, output,) = fee.verifyAndAttestOnChainV2(raw, 17, false);
        assertTrue(success, string(output));
    }

    function le32(uint32 value) internal pure returns (bytes4) {
        return bytes4((value >> 24) | ((value >> 8) & 0xff00) | ((value << 8) & 0xff0000) | (value << 24));
    }
}
