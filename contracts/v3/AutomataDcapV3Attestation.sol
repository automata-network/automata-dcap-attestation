//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAttestation} from "../interfaces/IAttestation.sol";
import {EnclaveIdBase, EnclaveIdTcbStatus, EnclaveId} from "../base/EnclaveIdBase.sol";
import {PEMCertChainBase, X509CertObj, PCKCertTCB, LibString, BytesUtils, CA} from "../base/PEMCertChainBase.sol";
import {TCBInfoBase, TCBLevelsObj, TCBStatus} from "../base/TCBInfoBase.sol";

import {V3Struct} from "./QuoteV3Auth/V3Struct.sol";
import {V3Parser} from "./QuoteV3Auth/V3Parser.sol";

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {Ownable} from "solady/auth/Ownable.sol";

contract AutomataDcapV3Attestation is IAttestation, EnclaveIdBase, PEMCertChainBase, TCBInfoBase, Ownable {
    using BytesUtils for bytes;
    using LibString for bytes;

    /// @dev partial data extracted from the journal to verify on-chain
    struct CollateralToBeVerified {
        bytes32 rootCaHash;
        bytes32 tcbSigningHash;
        bytes32 rootCaCrlHash;
        bytes32 pckCrlHash;
    }

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

    error Failed_To_Verify_Quote();
    error Invalid_Collateral_Hashes();

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
        bool verified;
        (verified, output) = _verify(input);
        if (!verified) {
            revert Failed_To_Verify_Quote();
        }
    }

    function verifyAndAttestWithZKProof(bytes calldata journal, bytes calldata seal)
        external
        view
        override
        returns (bytes memory output)
    {
        verifier.verify(seal, DCAP_RISC0_IMAGE_ID, sha256(journal));

        (CollateralToBeVerified memory collateral) = _getCollateralHashesFromJournal(journal);

        bool verifyHashes = _checkCollateralHashes(collateral);
        if (!verifyHashes) {
            revert Invalid_Collateral_Hashes();
        }

        output = journal[0:129];
    }

    /**
     * @dev may parse quotes off-chain, therefore slightly lowering gas cost as compared with { verifyAndAttestOnChain() }
     */
    function verifyParsedQuoteAndAttestOnChain(V3Struct.ParsedV3Quote calldata v3quote)
        external
        view
        returns (bytes memory output)
    {
        bool verified;
        (verified, output) =
            _verifyParsedQuote(v3quote, bytes(""), V3Parser.packQEReport(v3quote.v3AuthData.pckSignedQeReport));
        if (!verified) {
            revert Failed_To_Verify_Quote();
        }
    }

    /// @dev Provide the raw quote binary as input
    /// @dev view modifier omitted, because a PCCS cache miss emits an event
    /// @dev you can however, make a staticcall to this non-state changing method
    /// @return verified output: serialized as bytes of the following values:
    ///     uint8 tcbStatus ++ bytes32 isvMrEnclave ++ bytes32 isvMrSigner ++ bytes64 isvReportData
    function _verify(bytes calldata quote) private view returns (bool verified, bytes memory output) {
        // Parse the quote input
        (
            bool successful,
            V3Struct.ParsedV3Quote memory parsedV3Quote,
            bytes memory signedQuoteData,
            bytes memory rawQeReport
        ) = V3Parser.parseInput(quote);
        if (!successful) {
            return (false, output);
        }
        return _verifyParsedQuote(parsedV3Quote, signedQuoteData, rawQeReport);
    }

    /// @dev if the qupte is parsed on-chain, you must explicitly pass signedQuoteData here
    /// @dev view modifier omitted, because a PCCS cache miss emits an event
    /// @dev you can however, make a staticcall to this non-state changing method
    function _verifyParsedQuote(
        V3Struct.ParsedV3Quote memory v3quote,
        bytes memory signedQuoteData,
        bytes memory rawQeReport
    ) private view returns (bool verified, bytes memory output) {
        // Step 1: Only validate the parsed quote if provided off-chain (gas-saving)
        if (signedQuoteData.length == 0) {
            signedQuoteData = V3Parser.validateParsedInput(v3quote);
        }

        // Step 2: Verify enclave identity
        V3Struct.EnclaveReport memory qeEnclaveReport;
        EnclaveIdTcbStatus qeTcbStatus;
        {
            qeEnclaveReport = v3quote.v3AuthData.pckSignedQeReport;
            bool verifiedEnclaveIdSuccessfully;
            (verifiedEnclaveIdSuccessfully, qeTcbStatus) = _verifyQEReportWithIdentity(
                EnclaveId.QE,
                3,
                qeEnclaveReport.miscSelect,
                qeEnclaveReport.attributes,
                qeEnclaveReport.mrSigner,
                qeEnclaveReport.isvProdId,
                qeEnclaveReport.isvSvn
            );
            if (!verifiedEnclaveIdSuccessfully || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
                return (false, output);
            }
        }

        // Step 3: Parse Quote CertChain
        V3Struct.CertificationData memory certification = v3quote.v3AuthData.certification;
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
        {
            bool tcbInfoFound;
            (tcbInfoFound, tcbLevels) = _getTcbInfo(0, bytes6(pckTcb.fmspcBytes), 2);
            if (!tcbInfoFound) {
                return (false, output);
            }
        }

        // Step 5: Verify TCB Level
        TCBStatus tcbStatus;
        {
            // 4k gas
            bool tcbVerified;
            (tcbVerified, tcbStatus) = _checkTcbLevels(qeTcbStatus, pckTcb, tcbLevels);
            if (!tcbVerified) {
                return (false, output);
            }
        }

        // Step 6: Verify cert chain for certType == 5
        bool pckCertChainVerified = _verifyCertChain(parsedCerts);
        if (!pckCertChainVerified) {
            return (false, output);
        }

        // Step 7: Verify the local attestation sig and qe report sig = 670k gas
        {
            bool enclaveReportSigsVerified = _enclaveReportSigVerification(
                parsedCerts[0].subjectPublicKey, signedQuoteData, v3quote.v3AuthData, rawQeReport
            );
            if (!enclaveReportSigsVerified) {
                return (false, output);
            }
        }

        bytes memory rawIsvReport = V3Parser.packQEReport(v3quote.localEnclaveReport);

        output = _serializeOutput(tcbStatus, bytes6(pckTcb.fmspcBytes), rawIsvReport);

        return (true, output);
    }

    function _enclaveReportSigVerification(
        bytes memory pckCertPubKey,
        bytes memory signedQuoteData,
        V3Struct.ECDSAQuoteV3AuthData memory authDataV3,
        bytes memory rawQeReport
    ) private view returns (bool) {
        bytes32 expectedAuthDataHash = bytes32(authDataV3.pckSignedQeReport.reportData.substring(0, 32));
        bytes memory concatOfAttestKeyAndQeAuthData =
            abi.encodePacked(authDataV3.ecdsaAttestationKey, authDataV3.qeAuthData.data);
        bytes32 computedAuthDataHash = sha256(concatOfAttestKeyAndQeAuthData);

        bool qeReportDataIsValid = expectedAuthDataHash == computedAuthDataHash;
        if (qeReportDataIsValid) {
            bool qeSigVerified = _ecdsaVerify(sha256(rawQeReport), authDataV3.qeReportSignature, pckCertPubKey);
            bool quoteSigVerified =
                _ecdsaVerify(sha256(signedQuoteData), authDataV3.ecdsa256BitSignature, authDataV3.ecdsaAttestationKey);
            return qeSigVerified && quoteSigVerified;
        } else {
            return false;
        }
    }

    function _serializeOutput(TCBStatus tcbStatus, bytes6 fmspcBytes, bytes memory rawLocalIsvReport)
        private
        pure
        returns (bytes memory serialized)
    {
        require(rawLocalIsvReport.length == 384, "invalid isv report length");
        serialized = abi.encodePacked(
            uint16(3), // quote_version
            bytes4(0), // SGX_TEE_TYPE = 0x00000000
            tcbStatus,
            fmspcBytes,
            rawLocalIsvReport
        );
    }

    /// @dev the journal output has the following format:
    /// @dev serial_output_len = 2 bytes
    /// @dev serial_output (VerifiedOutput) = 397 bytes
    /// @dev current_time = 8 bytes
    /// @dev tcbinfov2_hash = 32 bytes
    /// @dev qeidentityv2_hash = 32 bytes
    /// ==============================================
    /// @notice the values below are extracted and verified on-chain
    /// @dev sgx_intel_root_ca_cert_hash = 32 bytes
    /// @dev sgx_tcb_signing_cert_hash = 32 bytes
    /// @dev sgx_tcb_intel_root_ca_crl_hash = 32 bytes
    /// @dev sgx_pck_pck_crl_hash = 32 bytes
    function _getCollateralHashesFromJournal(bytes calldata journal)
        private
        pure
        returns (CollateralToBeVerified memory output)
    {
        output.rootCaHash = bytes32(journal[471:503]);
        output.tcbSigningHash = bytes32(journal[503:535]);
        output.rootCaCrlHash = bytes32(journal[535:567]);
        output.pckCrlHash = bytes32(journal[567:599]);
    }

    function _checkCollateralHashes(CollateralToBeVerified memory output) private view returns (bool success) {
        (bool tcbSigningFound, bytes32 expectedTcbSigningHash) = _getCertHash(CA.SIGNING);
        if (!tcbSigningFound || output.tcbSigningHash != expectedTcbSigningHash) {
            return false;
        }
        (bool rootCaFound, bytes32 expectedRootCaHash) = _getCertHash(CA.ROOT);
        if (!rootCaFound || output.rootCaHash != expectedRootCaHash) {
            return false;
        }
        (bool rootCrlFound, bytes32 expectedRootCrlHash) = _getCrlHash(CA.ROOT);
        if (!rootCrlFound || output.rootCaCrlHash != expectedRootCrlHash) {
            return false;
        }
        (, bytes32 expectedPckPlatformCrlHash) = _getCrlHash(CA.PLATFORM);
        (, bytes32 expectedPckProcessorCrlHash) = _getCrlHash(CA.PROCESSOR);
        if (output.pckCrlHash != expectedPckPlatformCrlHash && output.pckCrlHash != expectedPckProcessorCrlHash) {
            return false;
        }

        return true;
    }
}
