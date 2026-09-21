// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "./AutomataDcapOnChainAttestationTest.t.sol";
import {AutomataDcapAttestationV2} from "../contracts/AutomataDcapAttestationV2.sol";

contract QuoteV3V4V2Test is AutomataDcapOnChainAttestationTest {
    function readHex(string memory name) internal view returns (bytes memory) {
        string memory raw = vm.readFile(string.concat(vm.projectRoot(), "/forge-test/assets/v2/", name, ".hex"));
        bytes memory content = bytes(raw);
        if (content[content.length - 1] == 0x0a) assembly ("memory-safe") { mstore(content, sub(mload(content), 1)) }
        return vm.parseBytes(string(content));
    }

    function verifyV2AndCompare(uint16 version) internal {
        vm.startPrank(admin);
        AutomataDcapAttestationV2 fee = new AutomataDcapAttestationV2(admin);
        fee.setQuoteVerifier(address(attestation.quoteVerifiers(version)));
        pccsRouter.setAuthorized(address(fee), true);
        vm.stopPrank();
        bytes memory quote = readHex(string.concat("quote-v", vm.toString(version)));
        (bool success, bytes memory output,) = fee.verifyAndAttestOnChainV2(quote);
        assertTrue(success, string(output));
        assertEq(
            output, readHex(string.concat("verified-v", vm.toString(version))), "Rust and Solidity output mismatch"
        );
    }

    function testRealV3V2MatchesRust() public {
        testQuoteV3OnChainAttestation();
        verifyV2AndCompare(3);
    }

    function testRealV4V2MatchesRust() public {
        testTDXQuoteV4OnChainAttestation();
        verifyV2AndCompare(4);
    }
}
