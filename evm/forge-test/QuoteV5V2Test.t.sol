// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "./QuoteV5Test.s.sol";
import {AutomataDcapAttestationFeeV2} from "../contracts/AutomataDcapAttestationFeeV2.sol";
import {OutputV2Codec} from "../contracts/utils/OutputV2Codec.sol";
import {OutputV2} from "../contracts/types/OutputV2.sol";

contract QuoteV5V2Test is QuoteV5Test {
    function decodeV2(bytes calldata output) external pure returns (OutputV2 memory) {
        return OutputV2Codec.decode(output);
    }

    function testRealQuoteV5V2() public {
        testQuoteV5TD15(); // Set up signed collateral and verify the same quote through the legacy selector.
        vm.startPrank(admin);
        AutomataDcapAttestationFeeV2 fee = new AutomataDcapAttestationFeeV2(admin);
        fee.setQuoteVerifier(address(attestation.quoteVerifiers(5)));
        pccsRouter.setAuthorized(address(fee), true);
        vm.stopPrank();
        bytes memory quote =
            vm.readFileBinary(string.concat(vm.projectRoot(), "/forge-test/assets/quotes/alibaba_quote_5.dat"));
        vm.expectRevert(bytes("TDX migration service TD measurement is not zero"));
        fee.verifyAndAttestOnChainV2(quote);
    }
}
