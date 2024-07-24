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
        Header memory header = _parseQuoteHeader(rawQuote);

        IQuoteVerifier quoteVerifier = quoteVerifiers[header.version];
        if (address(quoteVerifier) == address(0)) {
            return (false, bytes("Unsupported quote version"));
        }

        // We found a supported version, begin verifying the quote
        // Note: The quote header cannot be trusted yet, it will be validated by the Verifier library
        (success, output) = quoteVerifier.verifyQuote(header, rawQuote);
    }

    // the journal output has the following format:
    // serial_output_len (2 bytes)
    // serial_output (VerifiedOutput) (SGX: 397 bytes, TDX: 597 bytes)
    // current_time (8 bytes)
    // tcbinfov2_hash
    // qeidentityv2_hash
    // sgx_intel_root_ca_cert_hash
    // sgx_tcb_signing_cert_hash
    // sgx_tcb_intel_root_ca_crl_hash
    // sgx_pck_platform_crl_hash or sgx_pck_processor_crl_hash
    function verifyAndAttestWithZKProof(bytes calldata journal, bytes calldata seal)
        external
        view
        override
        returns (bool success, bytes memory output)
    {
        riscZeroVerifier.verify(seal, DCAP_RISC0_IMAGE_ID, sha256(journal));
        uint16 version = uint16(bytes2(journal[2:4]));
        IQuoteVerifier quoteVerifier = quoteVerifiers[version];
        if (address(quoteVerifier) == address(0)) {
            return (false, bytes("Unsupported quote version"));
        }

        (success, output) = quoteVerifier.verifyJournal(journal);
    }

    function _parseQuoteHeader(bytes calldata rawQuote) private pure returns (Header memory header) {
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
