// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "./QuoteV5Test.s.sol";
import {AutomataDcapAttestationV2} from "../contracts/AutomataDcapAttestationV2.sol";
import {OutputV2Codec} from "../contracts/utils/OutputV2Codec.sol";
import {OutputV2} from "../contracts/types/OutputV2.sol";

contract QuoteV5V2Test is QuoteV5Test {
    function decodeV2(bytes calldata output) external pure returns (OutputV2 memory) {
        return OutputV2Codec.decode(output);
    }

    function testRealQuoteV5V2() public {
        testQuoteV5TD15(); // Set up signed collateral and verify the same quote through the legacy selector.
        vm.startPrank(admin);
        AutomataDcapAttestationV2 fee = new AutomataDcapAttestationV2(admin);
        fee.setQuoteVerifier(address(attestation.quoteVerifiers(5)));
        pccsRouter.setAuthorized(address(fee), true);
        vm.stopPrank();
        bytes memory quote =
            vm.readFileBinary(string.concat(vm.projectRoot(), "/forge-test/assets/quotes/alibaba_quote_5.dat"));
        vm.expectRevert(bytes("TDX migration service TD measurement is not zero"));
        fee.verifyAndAttestOnChainV2(quote);
        vm.expectRevert(bytes("TDX migration service TD measurement is not zero"));
        fee.verifyAndAttestOnChainV2(quote, 0, false);
        (bool success, bytes memory output, bytes memory body) = fee.verifyAndAttestOnChainV2(quote, 0, true);
        assertTrue(success);
        OutputV2 memory decoded = this.decodeV2(output);
        assertEq(decoded.fullQuoteHash, keccak256(quote));
        assertEq(decoded.quoteBodyType, 3);
        assertEq(body.length, 648);
        assertEq(decoded.quoteBodyHash, keccak256(body));
        assertNotEq(keccak256(_serviceTd(body)), keccak256(new bytes(48)));
    }

    function _serviceTd(bytes memory body) internal pure returns (bytes memory measurement) {
        measurement = new bytes(48);
        for (uint256 i; i < 48; ++i) measurement[i] = body[600 + i];
    }
}
