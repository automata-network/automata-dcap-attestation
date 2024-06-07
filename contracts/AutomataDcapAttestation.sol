//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAttestation} from "./interfaces/IAttestation.sol";
import {BELE} from "./utils/BELE.sol";
import {IQuoteVerifier} from "./interfaces/IQuoteVerifier.sol";

import {Header} from "./types/CommonStruct.sol";
import "./types/Constants.sol";

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {Ownable} from "solady/auth/Ownable.sol";

contract AutomataDcapAttestation is IAttestation, Ownable {
    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public riscZeroVerifier;

    /// @notice The ImageID of the Risc0 DCAP Guest ELF
    bytes32 public DCAP_RISC0_IMAGE_ID;

    mapping(uint16 quoteVersion => IQuoteVerifier verifier) public quoteVerifiers;

    constructor(address risc0Verifier, bytes32 imageId) {
        _initializeOwner(msg.sender);
        riscZeroVerifier = IRiscZeroVerifier(risc0Verifier);
        DCAP_RISC0_IMAGE_ID = imageId;
    }

    function setQuoteVerifier(address verifier) external onlyOwner {
        IQuoteVerifier quoteVerifier = IQuoteVerifier(verifier);
        quoteVerifiers[quoteVerifier.quoteVersion()] = quoteVerifier;
    }

    function updateRisc0Config(address risc0Verifier, bytes32 imageId) external onlyOwner {
        riscZeroVerifier = IRiscZeroVerifier(risc0Verifier);
        DCAP_RISC0_IMAGE_ID = imageId;
    }

    function verifyAndAttestOnChain(bytes calldata rawQuote)
        external
        view
        override
        returns (bool success, bytes memory output)
    {
        // Parse the header
        Header memory header;
        string memory reason;
        (success, reason, header) = _parseQuoteHeader(rawQuote);
        if (!success) {
            return (success, bytes(reason));
        }

        IQuoteVerifier quoteVerifier = quoteVerifiers[header.version];
        if (address(quoteVerifier) == address(0)) {
            return (false, bytes("Unsupported quote version"));
        }

        // We found a supported version, begin verifying the quote body
        (success, output) = quoteVerifier.verifyQuote(header, rawQuote);
        if (!success) {
            return (false, output);
        }
    }

    function verifyAndAttestWithZKProof(bytes calldata journal, bytes32 postStateDigest, bytes calldata seal)
        external
        override
        returns (bool success, bytes memory output)
    {
        // TODO
    }

    function _parseQuoteHeader(bytes calldata rawQuote) private pure returns (bool, string memory, Header memory) {
        Header memory header;

        if (rawQuote.length < MINIMUM_QUOTE_LENGTH) {
            return (false, "Quote length is less than minimum", header);
        }

        bytes2 attestationKeyType = bytes2(rawQuote[2:4]);
        if (attestationKeyType != SUPPORTED_ATTESTATION_KEY_TYPE) {
            return (false, "Unsupported attestation key type", header);
        }

        bytes4 teeType = bytes4(rawQuote[4:8]);
        if (teeType != SGX_TEE && teeType != TDX_TEE) {
            return (false, "Unknown TEE type", header);
        }
        bytes2 qeSvn = bytes2(rawQuote[8:10]);
        bytes2 pceSvn = bytes2(rawQuote[10:12]);

        bytes16 qeVendorId = bytes16(rawQuote[12:28]);
        if (qeVendorId != VALID_QE_VENDOR_ID) {
            return (false, "Not a valid Intel SGX QE Vendor ID", header);
        }

        header = Header({
            version: uint16(BELE.leBytesToBeUint(rawQuote[0:2])),
            attestationKeyType: attestationKeyType,
            teeType: teeType,
            qeSvn: qeSvn,
            pceSvn: pceSvn,
            qeVendorId: qeVendorId,
            userData: bytes20(rawQuote[28:48])
        });

        return (true, "", header);
    }
}
