//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IQuoteVerifier} from "./interfaces/IQuoteVerifier.sol";

import {BELE} from "./utils/BELE.sol";
import "./types/Constants.sol";
import {Header} from "./types/CommonStruct.sol";
import {Ownable} from "solady/auth/Ownable.sol";

// ZK-Coprocessor imports:
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

enum ZkCoProcessorType {
    Unknown,
    RiscZero,
    Succinct
}

/**
 * @title ZK Co-Processor Configuration Object
 * @param dcapProgramIdentifier - This is the identifier of the ZK Program, required for
 * verification
 * @param zkVerifier - Points to the address of the ZK Verifier contract. Ideally
 * this should be pointing to a universal verifier, that may support multiple proof types and/or versions.
 */
struct ZkCoProcessorConfig {
    bytes32 dcapProgramIdentifier;
    address zkVerifier;
}

/**
 * @title DCAP Attestation Entrypoint Base contract
 * @notice Provides full implementation of both on-chain and ZK DCAP Verification
 */
abstract contract AttestationEntrypointBase is Ownable {
    // 51abd95c
    error Unknown_Zk_Coprocessor();

    mapping(ZkCoProcessorType => ZkCoProcessorConfig) _zkConfig;

    mapping(uint16 quoteVersion => IQuoteVerifier verifier) public quoteVerifiers;

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
     * @notice Sets the ZK Configuration for the given ZK Co-Processor
     */
    function setZkConfiguration(ZkCoProcessorType zkCoProcessor, ZkCoProcessorConfig memory config)
        external
        onlyOwner
    {
        _zkConfig[zkCoProcessor] = config;
    }

    /**
     * @param zkCoProcessorType 1 - RiscZero, 2 - Succinct... etc.
     * @return this is either the IMAGE_ID for RiscZero Guest Program or
     * Succiinct Program Verifying Key
     */
    function programIdentifier(uint8 zkCoProcessorType) external view returns (bytes32) {
        return _zkConfig[ZkCoProcessorType(zkCoProcessorType)].dcapProgramIdentifier;
    }

    /**
     * @notice get the contract verifier for the provided ZK Co-processor
     */
    function zkVerifier(uint8 zkCoProcessorType) external view returns (address) {
        return _zkConfig[ZkCoProcessorType(zkCoProcessorType)].zkVerifier;
    }

    /**
     * @notice full on-chain verification for an attestation
     * @param rawQuote - Intel DCAP Quote serialized in raw bytes
     * @return success - whether the quote has been successfully verified or not
     * @return output - the output upon completion of verification. The output data may require post-processing by the consumer.
     * For verification failures, the output is simply a UTF-8 encoded string, describing the reason for failure.
     * @dev can directly type-cast the failed output as a string
     */
    function _verifyAndAttestOnChain(bytes calldata rawQuote)
        internal
        view
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

    /**
     * @notice verifies an attestation using SNARK proofs
     * 
     * @param output - The output of the Guest program, this includes:
     * - VerifiedOutput struct
     * - RootCA hash
     * - TCB Signing CA hash
     * - Root CRL hash
     * - Platform or Processor CRL hash
     * @param zkCoprocessor - Specify ZK Co-Processor
     * @param proofBytes - The encoded cryptographic proof (i.e. SNARK)).
     */
    function _verifyAndAttestWithZKProof(
        bytes calldata output, 
        ZkCoProcessorType zkCoprocessor, 
        bytes calldata proofBytes
    )
        internal
        view
        returns (bool success, bytes memory verifiedOutput)
    {
        ZkCoProcessorConfig memory zkConfig = _zkConfig[zkCoprocessor];

        if (zkCoprocessor == ZkCoProcessorType.RiscZero) {
            IRiscZeroVerifier(zkConfig.zkVerifier).verify(
                proofBytes, zkConfig.dcapProgramIdentifier, sha256(output)
            );
        } else if (zkCoprocessor == ZkCoProcessorType.Succinct) {
            ISP1Verifier(zkConfig.zkVerifier).verifyProof(zkConfig.dcapProgramIdentifier, output, proofBytes);
        } else {
            revert Unknown_Zk_Coprocessor();
        }

        // verifies the output
        uint16 version = uint16(bytes2(output[2:4]));
        IQuoteVerifier quoteVerifier = quoteVerifiers[version];
        if (address(quoteVerifier) == address(0)) {
            return (false, bytes("Unsupported quote version"));
        }
        (success, verifiedOutput) = quoteVerifier.verifyZkOutput(output);
    }

    /**
     * @notice Parses the header to get basic information about the quote, such as the version, TEE types etc.
     */
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
