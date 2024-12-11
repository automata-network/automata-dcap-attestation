//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IQuoteVerifier} from "./interfaces/IQuoteVerifier.sol";

import {BELE} from "./utils/BELE.sol";
import "./types/Constants.sol";
import {Header} from "./types/CommonStruct.sol";
import {Ownable} from "solady/auth/Ownable.sol";

/**
 * @title DCAP Attestation Entrypoint Base contract
 * @notice Provides full implementation of both on-chain and ZK DCAP Verification
 */
contract AutomataDcapAttestation is Ownable {
    mapping(uint16 quoteVersion => IQuoteVerifier verifier)
        public quoteVerifiers;

    constructor() {
        _initializeOwner(msg.sender);
    }

    /**
     * @notice Sets the QuoteVerifier contract for specific DCAP quote version
     * @param verifier - the address of a version-specific QuoteVerifier contract
     */
    function setQuoteVerifier(address verifier) external onlyOwner {
        IQuoteVerifier quoteVerifier = IQuoteVerifier(verifier);
        quoteVerifiers[quoteVerifier.quoteVersion()] = quoteVerifier;
    }

    /**
     * @notice full on-chain verification for an attestation
     * @param rawQuote - Intel DCAP Quote serialized in raw bytes
     * @return success - whether the quote has been successfully verified or not
     * @return output - the output upon completion of verification. The output data may require post-processing by the consumer.
     * For verification failures, the output is simply a UTF-8 encoded string, describing the reason for failure.
     * @dev can directly type-cast the failed output as a string
     */
    function verifyAndAttestOnChain(
        bytes calldata rawQuote
    ) external view returns (bool success, bytes memory output) {
        // Parse the header
        Header memory header = _parseQuoteHeader(rawQuote);

        IQuoteVerifier quoteVerifier = quoteVerifiers[header.version];
        if (address(quoteVerifier) == address(0)) {
            return (false, bytes("Unsupported quote version"));
        }

        // We found a supported version, begin verifying the quote
        // Note: The quote header cannot be trusted yet, it will be validated by the Verifier library
        (success, output) = quoteVerifier.verifyQuote(header, rawQuote);
    }

    /**
     * @notice Parses the header to get basic information about the quote, such as the version, TEE types etc.
     */
    function _parseQuoteHeader(
        bytes calldata rawQuote
    ) private pure returns (Header memory header) {
        bytes2 attestationKeyType = bytes2(rawQuote[2:4]);
        bytes2 qeSvn = bytes2(rawQuote[8:10]);
        bytes2 pceSvn = bytes2(rawQuote[10:12]);
        bytes16 qeVendorId = bytes16(rawQuote[12:28]);

        header = Header({
            version: uint16(BELE.leBytesToBeUint(rawQuote[0:2])),
            attestationKeyType: attestationKeyType,
            teeType: bytes4(uint32(BELE.leBytesToBeUint(rawQuote[4:8]))),
            qeSvn: qeSvn,
            pceSvn: pceSvn,
            qeVendorId: qeVendorId,
            userData: bytes20(rawQuote[28:48])
        });
    }
}
