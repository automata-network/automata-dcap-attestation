//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {LibString} from "solady/utils/LibString.sol";

import "../bases/QuoteVerifierBase.sol";
import "../bases/TDXModuleBase.sol";
import "../bases/tcb/TCBInfoV3Base.sol";
import "../types/V4Structs.sol";

struct FetchedCollateralsAndStatuses {
    X509CertObj[] parsedCerts;
    PCKCertTCB pckTcb;
    TCBLevelsObj[] tcbLevels;
    TDXModule tdxModule;
    TDXModuleIdentity[] tdxModuleIdentities;
    EnclaveIdTcbStatus qeTcbStatus;
}

/**
 * @title Automata DCAP QuoteV4 Verifier
 */

contract V4QuoteVerifier is QuoteVerifierBase, TCBInfoV3Base, TDXModuleBase {
    using LibString for bytes;
    using BytesUtils for bytes;

    constructor(address _ecdsaVerifier, address _router) QuoteVerifierBase(_router, 4) P256Verifier(_ecdsaVerifier) {}

    function verifyZkOutput(bytes calldata outputBytes)
        external
        view
        override
        returns (bool success, bytes memory output)
    {
        bytes4 teeType = bytes4(outputBytes[4:8]);
        if (teeType != SGX_TEE && teeType != TDX_TEE) {
            return (false, bytes("Unknown TEE type"));
        }

        uint256 offset = 2 + uint16(bytes2(outputBytes[0:2]));

        success = checkCollateralHashes(offset + 72, outputBytes);
        if (success) {
            output = outputBytes[2:offset];
        } else {
            output = bytes("Found one or more collaterals mismatch");
        }
    }

    function verifyQuote(Header calldata header, bytes calldata rawQuote)
        external
        view
        override
        returns (bool success, bytes memory output)
    {
        string memory reason;
        bytes memory rawQuoteBody;
        bytes memory rawQeReport;
        ECDSAQuoteV4AuthData memory authData;
        (success, reason, rawQuoteBody, rawQeReport, authData) = _parseV4Quote(header, rawQuote);
        if (!success) {
            return (false, bytes(reason));
        }

        // we parsed the quote except for the body
        // parse body then verify quote
        bytes memory rawHeader = rawQuote[0:HEADER_LENGTH];
        bytes memory rawBody;
        if (header.teeType == SGX_TEE) {
            EnclaveReport memory localEnclaveReport;
            (success, localEnclaveReport) = parseEnclaveReport(rawQuoteBody);
            if (!success) {
                return (false, bytes("failed to parse local isv report"));
            }
            rawBody = rawQuote[HEADER_LENGTH:HEADER_LENGTH + ENCLAVE_REPORT_LENGTH];
            V4SGXQuote memory quote =
                V4SGXQuote({header: header, localEnclaveReport: localEnclaveReport, authData: authData});
            (success, output) = _verifySGXQuote(quote, rawHeader, rawBody, rawQeReport);
        } else if (header.teeType == TDX_TEE) {
            TD10ReportBody memory tdReport = parseTD10ReportBody(rawQuoteBody);
            rawBody = rawQuote[HEADER_LENGTH:HEADER_LENGTH + TD_REPORT10_LENGTH];
            V4TDXQuote memory quote = V4TDXQuote({header: header, reportBody: tdReport, authData: authData});
            (success, output) = _verifyTDXQuote(quote, rawHeader, rawBody, rawQeReport);
        } else {
            return (false, bytes("Unknown TEE type"));
        }
    }

    function _parseV4Quote(Header calldata header, bytes calldata quote)
        private
        view
        returns (
            bool success,
            string memory reason,
            bytes memory rawQuoteBody,
            bytes memory rawQeReport,
            ECDSAQuoteV4AuthData memory authData
        )
    {
        bytes4 teeType = header.teeType;
        (success, reason) = validateHeader(header, quote.length, teeType == SGX_TEE || teeType == TDX_TEE);
        if (!success) {
            return (success, reason, rawQuoteBody, rawQeReport, authData);
        }

        // now that we are able to confirm that the provided quote is a valid V4 SGX/TDX quote
        // based on information found in the header
        // we continue parsing the remainder of the quote

        uint256 offset = HEADER_LENGTH;
        if (teeType == SGX_TEE) {
            offset += ENCLAVE_REPORT_LENGTH;
        } else {
            offset += TD_REPORT10_LENGTH;
        }
        rawQuoteBody = quote[HEADER_LENGTH:offset];

        // check authData length
        uint256 localAuthDataSize = BELE.leBytesToBeUint(quote[offset:offset + 4]);
        offset += 4;
        if (quote.length - offset < localAuthDataSize) {
            return (false, "quote length is incorrect", rawQuoteBody, rawQeReport, authData);
        }

        // at this point, we have verified the length of the entire quote to be correct
        // parse authData
        (success, authData, rawQeReport) = parseAuthData(quote[offset:offset + localAuthDataSize]);
        if (!success) {
            return (false, "failed to parse authdata", rawQuoteBody, rawQeReport, authData);
        }
    }

    function _verifyCommon(
        bytes4 tee,
        bytes memory rawHeader,
        bytes memory rawBody,
        bytes memory rawQeReport,
        ECDSAQuoteV4AuthData memory authData
    ) private view returns (bool success, string memory reason, FetchedCollateralsAndStatuses memory ret) {
        // Step 0: Check QE Report Data
        success = verifyQeReportData(
            authData.qeReportCertData.qeReport.reportData,
            authData.ecdsaAttestationKey,
            authData.qeReportCertData.qeAuthData.data
        );
        if (!success) {
            return (success, "Invalid QEReport data", ret);
        }

        // Step 1: Fetch QEIdentity to validate TCB of the QE
        EnclaveIdTcbStatus qeTcbStatus;
        EnclaveId id = tee == SGX_TEE ? EnclaveId.QE : EnclaveId.TD_QE;
        EnclaveReport memory qeReport = authData.qeReportCertData.qeReport;
        (success, qeTcbStatus) = fetchQeIdentityAndCheckQeReport(id, qeReport);
        if (!success || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
            return (success, "Verification failed by QEIdentity check", ret);
        }

        // Step 2: Fetch FMSPC TCB
        X509CertObj[] memory parsedCerts = authData.qeReportCertData.certification.pck.pckChain;
        PCKCertTCB memory pckTcb = authData.qeReportCertData.certification.pck.pckExtension;
        TcbId tcbId = tee == SGX_TEE ? TcbId.SGX : TcbId.TDX;
        (
            bool tcbValid,
            TCBLevelsObj[] memory tcbLevels,
            TDXModule memory tdxModule,
            TDXModuleIdentity[] memory tdxModuleIdentities
        ) = pccsRouter.getFmspcTcbV3(tcbId, bytes6(pckTcb.fmspcBytes));
        if (!tcbValid) {
            return (false, "TCB not found or expired", ret);
        }

        // Step 3: verify cert chain
        success = verifyCertChain(pccsRouter, pccsRouter.crlHelperAddr(), parsedCerts);
        if (!success) {
            return (success, "Failed to verify X509 Chain", ret);
        }

        // Step 4: Signature Verification on local isv report and qereport by PCK
        bytes memory localAttestationData = abi.encodePacked(rawHeader, rawBody);
        success = attestationVerification(
            rawQeReport,
            authData.qeReportCertData.qeReportSignature,
            parsedCerts[0].subjectPublicKey,
            localAttestationData,
            authData.ecdsa256BitSignature,
            authData.ecdsaAttestationKey
        );
        if (!success) {
            return (success, "Failed to verify attestation and/or qe report signatures", ret);
        }

        ret.qeTcbStatus = qeTcbStatus;
        ret.parsedCerts = parsedCerts;
        ret.pckTcb = pckTcb;
        ret.tcbLevels = tcbLevels;
        ret.tdxModule = tdxModule;
        ret.tdxModuleIdentities = tdxModuleIdentities;
    }

    function _verifySGXQuote(
        V4SGXQuote memory quote,
        bytes memory rawHeader,
        bytes memory rawBody,
        bytes memory rawQeReport
    ) private view returns (bool success, bytes memory serialized) {
        // Step 1: Perform verification steps that are required for both SGX and TDX quotes
        string memory reason;
        FetchedCollateralsAndStatuses memory ret;
        (success, reason, ret) = _verifyCommon(quote.header.teeType, rawHeader, rawBody, rawQeReport, quote.authData);
        if (!success) {
            return (false, bytes(reason));
        }

        // Step 2: Check TCBStatus against isvs in the SGXComponent of the matching tcblevel
        TCBStatus tcbStatus;
        bool statusFound;
        uint256 tcbLevelSelected;
        for (uint256 i = 0; i < ret.tcbLevels.length; i++) {
            (statusFound, tcbStatus) = getSGXTcbStatus(ret.pckTcb, ret.tcbLevels[i]);
            if (statusFound) {
                tcbLevelSelected = i;
                break;
            }
        }
        if (!statusFound || tcbStatus == TCBStatus.TCB_REVOKED) {
            return (statusFound, bytes("Failed to locate a valid FMSPC TCB Status"));
        }

        // Step 3: Converge QEIdentity and FMSPC TCB Status
        tcbStatus = convergeTcbStatusWithQeTcbStatus(ret.qeTcbStatus, tcbStatus);

        Output memory output = Output({
            quoteVersion: quoteVersion,
            tee: SGX_TEE,
            tcbStatus: tcbStatus,
            fmspcBytes: bytes6(ret.pckTcb.fmspcBytes),
            quoteBody: rawBody,
            advisoryIDs: ret.tcbLevels[tcbLevelSelected].advisoryIDs
        });
        serialized = serializeOutput(output);
    }

    function _verifyTDXQuote(
        V4TDXQuote memory quote,
        bytes memory rawHeader,
        bytes memory rawBody,
        bytes memory rawQeReport
    ) private view returns (bool success, bytes memory serialized) {
        // Step 1: Perform verification steps that are required for both SGX and TDX quotes
        string memory reason;
        FetchedCollateralsAndStatuses memory ret;
        (success, reason, ret) = _verifyCommon(quote.header.teeType, rawHeader, rawBody, rawQeReport, quote.authData);
        if (!success) {
            return (false, bytes(reason));
        }

        // Step 2: Fetch FMSPC TCB
        // then get the TCB Status from the TDXComponenet of the matching TCBLevel
        TCBStatus tcbStatus;
        uint256 tcbLevelSelected;
        (success, tcbStatus, tcbLevelSelected) = getTDXTcbStatus(ret.tcbLevels, ret.pckTcb, quote.reportBody.teeTcbSvn);
        if (!success) {
            return (false, bytes("Failed to locate a valid FMSPC TCB Status"));
        }

        // Step 3: Fetch TDXModule TCB Status
        TCBStatus tdxModuleStatus;
        uint8 tdxModuleVersion;
        bytes memory expectedMrSignerSeam;
        bytes8 expectedSeamAttributes;
        (success, tdxModuleStatus, tdxModuleVersion, expectedMrSignerSeam, expectedSeamAttributes) =
            checkTdxModuleTcbStatus(quote.reportBody.teeTcbSvn, ret.tdxModuleIdentities);
        if (!success || tdxModuleStatus == TCBStatus.TCB_REVOKED) {
            return (false, bytes("Failed to locate a valid TDXModule TCB Status"));
        }

        // Step 4: TDX Module check
        success = checkTdxModule(
            quote.reportBody.mrsignerSeam, expectedMrSignerSeam, quote.reportBody.seamAttributes, expectedSeamAttributes
        );
        if (!success) {
            return (false, bytes("TDXModule check failed"));
        }

        // Step 5: Converge TDXModule and FMSPC TCB Status
        tcbStatus = convergeTcbStatusWithTdxModuleStatus(tcbStatus, tdxModuleStatus);

        // Step 6: Converge QEIdentity and TDX TCB Status
        tcbStatus = convergeTcbStatusWithQeTcbStatus(ret.qeTcbStatus, tcbStatus);

        Output memory output = Output({
            quoteVersion: quoteVersion,
            tee: TDX_TEE,
            tcbStatus: tcbStatus,
            fmspcBytes: bytes6(ret.pckTcb.fmspcBytes),
            quoteBody: rawBody,
            advisoryIDs: ret.tcbLevels[tcbLevelSelected].advisoryIDs
        });
        serialized = serializeOutput(output);
    }

    /**
     * @dev set visibility to internal because this can be reused by V5 or above QuoteVerifiers
     */
    function parseTD10ReportBody(bytes memory reportBytes) internal pure returns (TD10ReportBody memory report) {
        report.teeTcbSvn = bytes16(reportBytes.substring(0, 16));
        report.mrSeam = reportBytes.substring(16, 48);
        report.mrsignerSeam = reportBytes.substring(64, 48);
        report.seamAttributes = bytes8(uint64(BELE.leBytesToBeUint(reportBytes.substring(112, 8))));
        report.tdAttributes = bytes8(uint64(BELE.leBytesToBeUint(reportBytes.substring(120, 8))));
        report.xFAM = bytes8(uint64(BELE.leBytesToBeUint(reportBytes.substring(128, 8))));
        report.mrTd = reportBytes.substring(136, 48);
        report.mrConfigId = reportBytes.substring(184, 48);
        report.mrOwner = reportBytes.substring(232, 48);
        report.mrOwnerConfig = reportBytes.substring(280, 48);
        report.rtMr0 = reportBytes.substring(328, 48);
        report.rtMr1 = reportBytes.substring(376, 48);
        report.rtMr2 = reportBytes.substring(424, 48);
        report.rtMr3 = reportBytes.substring(472, 48);
        report.reportData = reportBytes.substring(520, 64);
    }

    /**
     * @dev set visibility to internal because this can be reused by V5 or above QuoteVerifiers
     *
     * [0:64] bytes: ecdsa256BitSignature
     * [64:128] bytes: ecdsaAttestationKey
     * [128:130] bytes: qeReportCertType
     * [130:134] bytes: qeReportCertSize (X)
     * NOTE: the calculations below assume qeReportCertType == 6
     * [134:518] bytes: qeReport
     * [518:582] bytes: qeReportSignature
     * [582:584] bytes: qeAuthDataSize (Y)
     * [584:584+Y] bytes: qeAuthData
     * [584+Y:586+Y] bytes: pckCertType
     * NOTE: the calculations below assume pckCertType == 5
     * [586+Y:590+Y] bytes: certSize (Z)
     * [590+Y:590+Y+Z] bytes: certData
     */
    function parseAuthData(bytes calldata rawAuthData)
        internal
        view
        returns (bool success, ECDSAQuoteV4AuthData memory authDataV4, bytes memory rawQeReport)
    {
        authDataV4.ecdsa256BitSignature = rawAuthData[0:64];
        authDataV4.ecdsaAttestationKey = rawAuthData[64:128];

        uint256 qeReportCertType = BELE.leBytesToBeUint(rawAuthData[128:130]);
        if (qeReportCertType != 6) {
            return (false, authDataV4, rawQeReport);
        }
        uint256 qeReportCertSize = BELE.leBytesToBeUint(rawAuthData[130:134]);

        rawQeReport = rawAuthData[134:518];
        authDataV4.qeReportCertData.qeReportSignature = rawAuthData[518:582];

        uint16 qeAuthDataSize = uint16(BELE.leBytesToBeUint(rawAuthData[582:584]));
        authDataV4.qeReportCertData.qeAuthData.parsedDataSize = qeAuthDataSize;
        uint256 offset = 584;
        authDataV4.qeReportCertData.qeAuthData.data = rawAuthData[offset:offset + qeAuthDataSize];
        offset += qeAuthDataSize;

        uint16 certType = uint16(BELE.leBytesToBeUint(rawAuthData[offset:offset + 2]));
        // we only support certType == 5 for now...
        if (certType != 5) {
            return (false, authDataV4, rawQeReport);
        }

        authDataV4.qeReportCertData.certification.certType = certType;
        offset += 2;
        uint32 certDataSize = uint32(BELE.leBytesToBeUint(rawAuthData[offset:offset + 4]));
        offset += 4;
        authDataV4.qeReportCertData.certification.certDataSize = certDataSize;
        bytes memory rawCertData = rawAuthData[offset:offset + certDataSize];
        offset += certDataSize;

        if (offset - 134 != qeReportCertSize) {
            return (false, authDataV4, rawQeReport);
        }

        // parsing complete, now we need to decode some raw data

        (success, authDataV4.qeReportCertData.qeReport) = parseEnclaveReport(rawQeReport);
        if (!success) {
            return (false, authDataV4, rawQeReport);
        }

        (success, authDataV4.qeReportCertData.certification.pck) =
            getPckCollateral(pccsRouter.pckHelperAddr(), certType, rawCertData);
        if (!success) {
            return (false, authDataV4, rawQeReport);
        }
    }
}
