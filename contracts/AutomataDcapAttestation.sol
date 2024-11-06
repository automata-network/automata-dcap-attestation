//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAttestation} from "./interfaces/IAttestation.sol";
import {IQuoteVerifier} from "./interfaces/IQuoteVerifier.sol";
import {IZKVerifier} from "./interfaces/IZKVerifier.sol";

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

struct ZkCoProcessorConfig {
    bytes32 dcapProgramIdentifier;
    address zkVerifier;
}

contract AutomataDcapAttestation is IAttestation, IZKVerifier, Ownable {
    mapping(ZkCoProcessorType => ZkCoProcessorConfig) _zkConfig;

    mapping(uint16 quoteVersion => IQuoteVerifier verifier) public quoteVerifiers;

    constructor() {
        _initializeOwner(msg.sender);
    }

    function setQuoteVerifier(address verifier) external onlyOwner {
        IQuoteVerifier quoteVerifier = IQuoteVerifier(verifier);
        quoteVerifiers[quoteVerifier.quoteVersion()] = quoteVerifier;
    }

    function setZkConfiguration(ZkCoProcessorType zkCoProcessor, ZkCoProcessorConfig memory config)
        external
        onlyOwner
    {
        _zkConfig[zkCoProcessor] = config;
    }

    function programIdentifier(uint8 zkCoProcessorType) external view override returns (bytes32) {
        return _zkConfig[ZkCoProcessorType(zkCoProcessorType)].dcapProgramIdentifier;
    }

    function zkVerifier(uint8 zkCoProcessorType) external view returns (address) {
        return _zkConfig[ZkCoProcessorType(zkCoProcessorType)].zkVerifier;
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

    function verifyAndAttestWithZKProof(bytes calldata output, bytes calldata proofBytes)
        external
        view
        override
        returns (bool success, bytes memory verifiedOutput)
    {
        ZkCoProcessorType zkCoprocessor = ZkCoProcessorType(uint8(bytes1(proofBytes[0:1])));
        ZkCoProcessorConfig memory zkConfig = _zkConfig[zkCoprocessor];

        if (zkCoprocessor == ZkCoProcessorType.RiscZero) {
            IRiscZeroVerifier(zkConfig.zkVerifier).verify(
                proofBytes[1:], zkConfig.dcapProgramIdentifier, sha256(output)
            );
        } else if (zkCoprocessor == ZkCoProcessorType.Succinct) {
            ISP1Verifier(zkConfig.zkVerifier).verifyProof(zkConfig.dcapProgramIdentifier, output, proofBytes[1:]);
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
