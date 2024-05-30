//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAttestation} from "../interfaces/IAttestation.sol";

import {EnclaveIdBase, EnclaveIdTcbStatus, EnclaveId} from "../base/EnclaveIdBase.sol";
import {PEMCertChainBase, X509CertObj, PCKCertTCB, LibString, BytesUtils, CA} from "../base/PEMCertChainBase.sol";
import {TCBInfoBase, TCBLevelsObj, TCBStatus, TcbId, TDXModule, TDXModuleIdentity} from "../base/TCBInfoBase.sol";

import {V4Struct} from "./QuoteV4/V4Struct.sol";
import {V4Parser, TeeType} from "./QuoteV4/V4Parser.sol";

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {Ownable} from "solady/auth/Ownable.sol";

contract AutomataDcapV4Attestation is IAttestation, EnclaveIdBase, PEMCertChainBase, TCBInfoBase, Ownable {
    using BytesUtils for bytes;
    using LibString for bytes;

    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public verifier;

    /// @notice The ImageID of the Risc0 DCAP Guest ELF
    bytes32 public DCAP_RISC0_IMAGE_ID;

    constructor(
        address enclaveIdDaoAddr,
        address enclaveIdHelperAddr,
        address pckHelperAddr,
        address tcbDaoAddr,
        address tcbHelperAddr,
        address crlHelperAddr,
        address pcsDaoAddr,
        address risc0Verifier,
        bytes32 imageId
    )
        EnclaveIdBase(enclaveIdDaoAddr, enclaveIdHelperAddr)
        PEMCertChainBase(pckHelperAddr, crlHelperAddr, pcsDaoAddr)
        TCBInfoBase(tcbDaoAddr, tcbHelperAddr)
    {
        _initializeOwner(msg.sender);
        verifier = IRiscZeroVerifier(risc0Verifier);
        DCAP_RISC0_IMAGE_ID = imageId;
    }

    function updateConfig(
        address enclaveIdDaoAddr,
        address enclaveIdHelperAddr,
        address pckHelperAddr,
        address tcbDaoAddr,
        address tcbHelperAddr,
        address crlHelperAddr,
        address pcsDaoAddr
    ) external onlyOwner {
        _setEnclaveIdBaseConfig(enclaveIdDaoAddr, enclaveIdHelperAddr);
        _setCertBaseConfig(pckHelperAddr, crlHelperAddr, pcsDaoAddr);
        _setTcbBaseConfig(tcbDaoAddr, tcbHelperAddr);
    }

    function updateRisc0Config(address risc0Verifier, bytes32 imageId) external onlyOwner {
        verifier = IRiscZeroVerifier(risc0Verifier);
        DCAP_RISC0_IMAGE_ID = imageId;
    }

    function verifyAndAttestOnChain(bytes calldata input) external view override returns (bytes memory output) {
        (V4Struct.ParsedV4Quote memory parsedQuote, bytes memory quoteDataBytes, bytes memory qeReportBytes) =
            V4Parser.parseInput(input);
        bool verified;
        string memory reason;
        (verified, reason, output) = _verifyParseQuote(parsedQuote, quoteDataBytes, qeReportBytes);
        require(verified, reason);
    }

    function verifyParsedQuoteAndAttestOnChain(V4Struct.ParsedV4Quote calldata parsedQuote)
        external
        view
        returns (bytes memory output)
    {
        bool verified;
        string memory reason;

        bytes memory headerBytes = abi.encodePacked(
            parsedQuote.header.version,
            parsedQuote.header.attestationKeyType,
            parsedQuote.header.teeType,
            parsedQuote.header.reserved,
            parsedQuote.header.qeVendorId,
            parsedQuote.header.userData
        );

        V4Struct.ReportBody memory reportBody = parsedQuote.reportBody;
        bytes memory reportBodyBytes = abi.encodePacked(
            reportBody.teeTcbSvn,
            reportBody.mrSeam,
            reportBody.mrsignerSeam,
            reportBody.seamAttributes,
            reportBody.tdAttributes,
            reportBody.xFAM,
            reportBody.mrTd,
            reportBody.mrConfigId,
            reportBody.mrOwnerConfig,
            reportBody.rtMr0,
            reportBody.rtMr1,
            reportBody.rtMr2,
            reportBody.rtMr3,
            reportBody.reportData
        );

        bytes memory quoteReportBytes = V4Parser.packQEReport(parsedQuote.authData.qeReportCertData.qeReport);

        (verified, reason, output) =
            _verifyParseQuote(parsedQuote, abi.encodePacked(headerBytes, reportBodyBytes), quoteReportBytes);
        require(verified, reason);
    }

    function verifyAndAttestWithZKProof(bytes calldata journal, bytes32 postStateDigest, bytes calldata seal)
        external
        view
        override
        returns (bytes memory output)
    {
        // TODO
    }

    function _verifyParseQuote(
        V4Struct.ParsedV4Quote memory parsedQuote,
        bytes memory quoteDataBytes,
        bytes memory qeReportBytes
    ) private view returns (bool verified, string memory reason, bytes memory output) {
        // Step 1: Validate the quote
        V4Struct.QEReportCertificationData memory qeReportCert = parsedQuote.authData.qeReportCertData;
        TeeType tee;
        (verified, reason, tee) = V4Parser.validateParsedInput(parsedQuote);
        if (!verified) {
            return (verified, reason, output);
        }

        // Step 2: Verify enclave identity
        V4Struct.EnclaveReport memory qeEnclaveReport;
        EnclaveIdTcbStatus qeTcbStatus;
        {
            EnclaveId enclaveId = tee == TeeType.SGX ? EnclaveId.QE : EnclaveId.TD_QE;
            qeEnclaveReport = qeReportCert.qeReport;
            bool verifiedEnclaveIdSuccessfully;
            (verifiedEnclaveIdSuccessfully, qeTcbStatus) = _verifyQEReportWithIdentity(
                enclaveId,
                4,
                qeEnclaveReport.miscSelect,
                qeEnclaveReport.attributes,
                qeEnclaveReport.mrSigner,
                qeEnclaveReport.isvProdId,
                qeEnclaveReport.isvSvn
            );
            if (!verifiedEnclaveIdSuccessfully || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
                return (false, "QEIdentity verification failed", output);
            }
        }

        // Step 3: Parse Quote CertChain
        V4Struct.CertificationData memory certification = qeReportCert.certData;
        X509CertObj[] memory parsedCerts;
        PCKCertTCB memory pckTcb;
        {
            bytes[] memory certs = certification.decodedCertDataArray;
            uint256 chainSize = certs.length;
            parsedCerts = new X509CertObj[](chainSize);
            for (uint256 i = 0; i < chainSize; i++) {
                parsedCerts[i] = pckHelper.parseX509DER(certs[i]);
                // additional parsing for PCKCert
                if (i == 0) {
                    pckTcb = _parsePck(certs[0], parsedCerts[0].extensionPtr);
                }
            }
        }

        // Step 4: basic PCK and TCB check
        TCBLevelsObj[] memory tcbLevels;
        TcbId tcbType = tee == TeeType.SGX ? TcbId.SGX : TcbId.TDX;
        TDXModule memory tdxModule;
        TDXModuleIdentity[] memory tdxModuleIdentities;
        {
            bool tcbInfoFound;
            (tcbInfoFound, tcbLevels, tdxModule, tdxModuleIdentities) =
                _getTcbInfo(tcbType, pckTcb.fmspcBytes.toHexStringNoPrefix(), 3);
            if (!tcbInfoFound) {
                return (false, "TCBInfo not found!", output);
            }
        }

        // Step 5: Verify TCB Level
        TCBStatus tcbStatus;
        bytes16 teeTcbSvn = parsedQuote.reportBody.teeTcbSvn;
        bytes memory expectedMrSignerSeam;
        bytes8 expectedSeamAttributes;
        {
            bool tcbVerified;

            (tcbVerified, tcbStatus, expectedMrSignerSeam, expectedSeamAttributes) = _checkTcbLevelsForV4Quotes(
                qeTcbStatus, pckTcb, tcbType, teeTcbSvn, tcbLevels, tdxModule, tdxModuleIdentities
            );
            if (!tcbVerified) {
                return (false, "Failed to verify TCBLevels!", output);
            }
        }

        // Step 6: TDX Module check
        if (tee == TeeType.TDX) {
            bool mrsignerSeamIsValid = keccak256(parsedQuote.reportBody.mrsignerSeam) == keccak256(expectedMrSignerSeam);
            bool seamAttributeIsValid = keccak256(abi.encodePacked(parsedQuote.reportBody.seamAttributes))
                == keccak256(abi.encodePacked(expectedSeamAttributes));
            if (!mrsignerSeamIsValid || !seamAttributeIsValid) {
                return (false, "Invalid TDX Module", output);
            }
        }

        // Step 7: Verify cert chain only for certType == 5
        // this is because the PCK Certificate Chain is not obtained directly from on-chain PCCS
        // which is untrusted and requires validation
        bool pckCertChainVerified = _verifyCertChain(parsedCerts);
        if (!pckCertChainVerified) {
            return (false, "Failed to verify PCK Chain!", output);
        }

        // Step 8: Verify the local attestation sig and qe report sig = 670k gas
        {
            bool enclaveReportSigsVerified = _enclaveReportSigVerification(
                parsedCerts[0].subjectPublicKey, quoteDataBytes, qeReportBytes, parsedQuote.authData
            );
            if (!enclaveReportSigsVerified) {
                return (false, "Failed to verify report body or quote report", output);
            }
        }

        // TODO: serialize output
    }

    function _enclaveReportSigVerification(
        bytes memory pckCertPubKey,
        bytes memory quoteDataBytes,
        bytes memory qeReportBytes,
        V4Struct.ECDSAQuoteV4AuthData memory authDataV4
    ) private view returns (bool) {
        bytes32 expectedAuthDataHash = bytes32(authDataV4.qeReportCertData.qeReport.reportData.substring(0, 32));
        bytes memory concatOfAttestKeyAndQeAuthData =
            abi.encodePacked(authDataV4.ecdsaAttestationKey, authDataV4.qeReportCertData.qeAuthData.data);
        bytes32 computedAuthDataHash = sha256(concatOfAttestKeyAndQeAuthData);

        bool qeReportDataIsValid = expectedAuthDataHash == computedAuthDataHash;
        if (qeReportDataIsValid) {
            bool qeSigVerified =
                _ecdsaVerify(sha256(qeReportBytes), authDataV4.qeReportCertData.qeReportSignature, pckCertPubKey);
            bool quoteSigVerified =
                _ecdsaVerify(sha256(quoteDataBytes), authDataV4.ecdsa256BitSignature, authDataV4.ecdsaAttestationKey);
            return qeSigVerified && quoteSigVerified;
        } else {
            return false;
        }
    }
}
