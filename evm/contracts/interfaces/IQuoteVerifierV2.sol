// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import {IQuoteVerifier, Header} from "./IQuoteVerifier.sol";

interface IQuoteVerifierV2 is IQuoteVerifier {
    /// @dev On success returns abi.encode(ppid, piid, piidPresent, legacyFields).
    /// Internal transport only; FeeV2 emits/returns canonical OutputV2, never this envelope.
    function verifyQuoteV2(Header calldata header, bytes calldata rawQuote, uint32 tcbEvalNumber)
        external
        view
        returns (bool, bytes memory);
}
