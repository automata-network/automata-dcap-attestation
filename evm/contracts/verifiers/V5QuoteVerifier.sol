//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {LibString} from "solady/utils/LibString.sol";

import "../utils/TDReportParser.sol";
import "../bases/QuoteVerifierBase.sol";
import "../bases/TDXModuleBase.sol";
import "../bases/tcb/TCBInfoV3Base.sol";
import "../types/V5Structs.sol";

contract V5QuoteVerifier is QuoteVerifierBase, TCBInfoV3Base, TDXModuleBase {
    uint8 constant TCB_TD_RELAUNCH_ADVISED = 8;
    uint8 constant TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED = 9;

    constructor(address _ecdsaVerifier, address _router) QuoteVerifierBase(_router, 5) P256Verifier(_ecdsaVerifier) {}

    function verifyZkOutput(bytes calldata outputBytes, uint32 tcbEvalNumber)
        external
        view
        override
        returns (bool success, bytes memory output)
    {
        bytes4 teeType = bytes4(outputBytes[4:8]);
        if (teeType != SGX_TEE && teeType != TDX_TEE) {
            return (false, bytes("Unknown TEE type"));
        }

        uint16 outputLength = uint16(bytes2(outputBytes[0:2]));
        uint256 offset = 2 + outputLength;
        if (offset + VERIFIED_OUTPUT_COLLATERAL_HASHES_LENGTH != outputBytes.length) {
            return (false, "invalid output length");
        }
        bytes memory errorMessage;
        (success, errorMessage) = checkCollateralHashes(tcbEvalNumber, offset, outputBytes);
        output = success ? outputBytes[2:offset] : errorMessage;
    }

    function verifyQuote(Header calldata header, bytes calldata rawQuote, uint32 tcbEvalNumber)
        external
        view
        override
        returns (bool success, bytes memory serializedOutput)
    {
        string memory reason;
        bytes memory rawQeReport;
        uint32 quoteBodySize;
        ECDSAQuoteV4AuthData memory authData;

        (success, reason, quoteBodySize, rawQeReport, authData) = _parseV5Quote(header, rawQuote);
        if (!success) {
            return (false, bytes(reason));
        }

        // begin the verification process
        bytes4 tee = header.teeType;
        TcbId tcbId = tee == SGX_TEE ? TcbId.SGX : TcbId.TDX;

        // Step 0: Determine the TCB evaluation data number if not specified
        if (tcbEvalNumber == 0) {
            tcbEvalNumber = pccsRouter.getStandardTcbEvaluationDataNumber(tcbId);
        }

        // Step 1: Check QE Report Data
        success = verifyQeReportData(
            authData.qeReportCertData.qeReport.reportData,
            authData.ecdsaAttestationKey,
            authData.qeReportCertData.qeAuthData.data
        );
        if (!success) {
            return (false, bytes("Invalid QE Report Data"));
        }

        // Step 2: Get the TCB Status of the QE
        EnclaveIdTcbStatus qeTcbStatus;
        {
            EnclaveId id = tee == SGX_TEE ? EnclaveId.QE : EnclaveId.TD_QE;
            EnclaveReport memory qeReport = authData.qeReportCertData.qeReport;
            (success, qeTcbStatus) = fetchQeIdentityAndCheckQeReport(id, qeReport, tcbEvalNumber);
            if (!success || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
                return (success, "Verification failed by QEIdentity check");
            }
        }

        X509CertObj[] memory parsedCerts = authData.qeReportCertData.certification.pck.pckChain;
        {
            // Step 3: Verify the local attestation
            bytes memory localAttestationData = abi.encodePacked(
                rawQuote[0:HEADER_LENGTH], // quote header
                rawQuote[HEADER_LENGTH:HEADER_LENGTH + 2 + 4 + quoteBodySize] // quote body
            );
            success = attestationVerification(
                rawQeReport,
                authData.qeReportCertData.qeReportSignature,
                parsedCerts[0].subjectPublicKey,
                localAttestationData,
                authData.ecdsa256BitSignature,
                authData.ecdsaAttestationKey
            );
            if (!success) {
                return (success, "Failed to verify attestation and/or qe report signatures");
            }
        }

        // Step 4: Verify cert chain
        success = verifyCertChain(pccsRouter, pccsRouter.crlHelperAddr(), parsedCerts);
        if (!success) {
            return (success, "Failed to verify X509 Chain");
        }

        // Step 5: Fetch FMSPC TCB Collateral, and the matching TCB Status
        PCKCertTCB memory pckTcb = authData.qeReportCertData.certification.pck.pckExtension;
        (TCBLevelsObj[] memory tcbLevels, TDXModule memory tdxModule, TDXModuleIdentity[] memory tdxModuleIdentities) =
            pccsRouter.getFmspcTcbV3(tcbId, bytes6(pckTcb.fmspcBytes), tcbEvalNumber);

        uint8 tcbStatus = uint8(TCBStatus.TCB_UNRECOGNIZED);
        uint256 tcbLevelSelected = TCB_LEVEL_ERROR;
        uint256 bodyOffset = HEADER_LENGTH + 2 + 4;

        if (tee == SGX_TEE) {
            bool statusFound;
            TCBStatus sgxStatus;
            for (uint256 i = 0; i < tcbLevels.length; i++) {
                (statusFound, sgxStatus) = getSGXTcbStatus(pckTcb, tcbLevels[i]);
                if (statusFound) {
                    tcbLevelSelected = i;
                    break;
                }
            }
            sgxStatus = convergeTcbStatusWithQeTcbStatus(qeTcbStatus, sgxStatus);
            tcbStatus = uint8(sgxStatus);
        } else {
            bytes16 teeTcbSvn;
            bytes memory mrSignerSeam;
            bytes8 seamAttributes;
            bytes16 teeTcbSvn2;

            (success, reason, teeTcbSvn, mrSignerSeam, seamAttributes, teeTcbSvn2) =
                _parseTdReport(rawQuote[bodyOffset:bodyOffset + quoteBodySize]);
            if (!success) {
                return (false, bytes(reason));
            }

            TCBStatus sgxStatus = TCBStatus.TCB_UNRECOGNIZED;
            TCBStatus tdxStatus = TCBStatus.TCB_UNRECOGNIZED;
            (success, sgxStatus, tdxStatus, tcbLevelSelected) = getTDXTcbStatus(tcbLevels, pckTcb, teeTcbSvn);
            if (!success || tdxStatus == TCBStatus.TCB_REVOKED) {
                return (false, "Failed to get TDX TCB status");
            }

            TCBStatus tdxModuleStatus;
            {
                bytes memory expectedMrSignerSeam = tdxModule.mrsigner;
                bytes8 expectedSeamAttributes = tdxModule.attributes;
                (success, tdxModuleStatus, expectedMrSignerSeam, expectedSeamAttributes) =
                    checkTdxModuleTcbStatus(teeTcbSvn, tdxModuleIdentities);
                if (!success || tdxModuleStatus == TCBStatus.TCB_REVOKED) {
                    return (false, bytes("Failed to locate a valid TDXModule TCB Status"));
                }

                success = checkTdxModule(mrSignerSeam, expectedMrSignerSeam, seamAttributes, expectedSeamAttributes);
                if (!success) {
                    return (false, bytes("TDXModule check failed"));
                }
            }

            tdxStatus = convergeTcbStatusWithTdxModuleStatus(tdxStatus, tdxModuleStatus);
            tcbStatus = uint8(convergeTcbStatusWithQeTcbStatus(qeTcbStatus, tdxStatus));

            if (quoteBodySize == TD_REPORT15_LENGTH) {
                // Relaunch check (TD 1.5 only)
                bool relaunchAdvised;
                bool configurationNeeded;
                (success, reason, relaunchAdvised, configurationNeeded) = _relaunchCheck(
                    teeTcbSvn2, qeTcbStatus, sgxStatus, tdxStatus, tcbLevels, tdxModuleIdentities
                );
                if (!success) {
                    return (false, bytes(reason));
                }
                if (relaunchAdvised) {
                    tcbStatus =
                        configurationNeeded ? TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED : TCB_TD_RELAUNCH_ADVISED;
                }
            }
        }

        // Step 6: Generate Output
        Output memory output = Output({
            quoteVersion: quoteVersion,
            tee: tee,
            tcbStatus: tcbStatus,
            fmspcBytes: bytes6(pckTcb.fmspcBytes),
            quoteBody: rawQuote[bodyOffset:bodyOffset + quoteBodySize],
            advisoryIDs: tcbLevels[tcbLevelSelected].advisoryIDs
        });

        serializedOutput = serializeOutput(output);
    }

    function _parseV5Quote(Header calldata header, bytes calldata quote)
        private
        view
        returns (
            bool success,
            string memory reason,
            uint32 quoteBodySize,
            bytes memory rawQeReport,
            ECDSAQuoteV4AuthData memory authData
        )
    {
        bytes4 teeType = header.teeType;
        (success, reason) = validateHeader(header, quote.length, teeType == SGX_TEE || teeType == TDX_TEE);
        if (!success) {
            return (success, reason, 0, rawQeReport, authData);
        }

        // now that we are able to confirm that the provided quote is a valid V5 SGX/TDX quote
        // based on information found in the header
        // we continue parsing the remainder of the quote

        uint256 offset = HEADER_LENGTH;

        // get the body
        uint16 quoteBodyType = uint16(BELE.leBytesToBeUint(quote[offset:offset + 2]));
        offset += 2;

        uint32 expectedBodySize;
        if (teeType == SGX_TEE) {
            if (quoteBodyType != 1) {
                return (false, "Invalid body type for SGX quote", 0, rawQeReport, authData);
            }
            expectedBodySize = ENCLAVE_REPORT_LENGTH;
        } else {
            if (quoteBodyType == 2) {
                // TD1.0 report
                expectedBodySize = TD_REPORT10_LENGTH;
            } else if (quoteBodyType == 3) {
                // TD1.5 report
                expectedBodySize = TD_REPORT15_LENGTH;
            } else {
                return (false, "Invalid body type for TDX quote", 0, rawQeReport, authData);
            }
        }

        quoteBodySize = uint32(BELE.leBytesToBeUint(quote[offset:offset + 4]));
        if (quoteBodySize != expectedBodySize) {
            return (false, "Invalid body size", 0, rawQeReport, authData);
        }
        offset += 4 + quoteBodySize;

        // check authData length
        uint256 localAuthDataSize = BELE.leBytesToBeUint(quote[offset:offset + 4]);
        offset += 4;
        // we don't strictly require the auth data to be equal to the provided length
        // but this ignores any trailing bytes after the indicated length allocated for authData
        if (quote.length - offset < localAuthDataSize) {
            return (false, "quote auth data length is incorrect", 0, rawQeReport, authData);
        }

        // at this point, we have verified the length of the entire quote to be correct
        // parse authData
        (success, authData, rawQeReport) = _parseAuthData(quote[offset:offset + localAuthDataSize]);
        if (!success) {
            return (false, "failed to parse authdata", 0, rawQeReport, authData);
        }
    }

    function _parseAuthData(bytes calldata rawAuthData)
        private
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

    function _parseTdReport(bytes calldata rawTdReport)
        private
        pure
        returns (
            bool success,
            string memory reason,
            bytes16 teeTcbSvn,
            bytes memory mrSignerSeam,
            bytes8 seamAttributes,
            bytes16 teeTcbSvn2
        )
    {
        if (rawTdReport.length == TD_REPORT10_LENGTH) {
            TD10ReportBody memory td10ReportBody;
            (success, td10ReportBody) = TD10ReportParser.parse(rawTdReport);
            if (!success) {
                return (false, "Failed to parse TD10 report body", teeTcbSvn, mrSignerSeam, seamAttributes, teeTcbSvn2);
            }
            teeTcbSvn = td10ReportBody.teeTcbSvn;
            mrSignerSeam = td10ReportBody.mrsignerSeam;
            seamAttributes = td10ReportBody.seamAttributes;
        } else {
            TD15ReportBody memory td15ReportBody;
            (success, td15ReportBody) = TD15ReportParser.parse(rawTdReport);
            if (!success) {
                return (false, "Failed to parse TD15 report body", teeTcbSvn, mrSignerSeam, seamAttributes, teeTcbSvn2);
            }
            teeTcbSvn = td15ReportBody.teeTcbSvn;
            teeTcbSvn2 = td15ReportBody.teeTcbSvn2;
            mrSignerSeam = td15ReportBody.mrsignerSeam;
            seamAttributes = td15ReportBody.seamAttributes;
        }
    }

    /// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/stable/Src/AttestationLibrary/src/Verifiers/Checks/TDRelaunchCheck.cpp
    function _relaunchCheck(
        bytes16 teeTcbSvn2,
        EnclaveIdTcbStatus qeTcbStatus,
        TCBStatus sgxStatus,
        TCBStatus tdxStatus,
        TCBLevelsObj[] memory tcbLevels,
        TDXModuleIdentity[] memory tdxModuleIdentities
    ) private pure returns (bool success, string memory reason, bool relaunchAdvised, bool configurationNeeded) {
        if (qeTcbStatus != EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE) {
            if (sgxStatus != TCBStatus.TCB_OUT_OF_DATE || sgxStatus != TCBStatus.TCB_OUT_OF_DATE_CONFIGURATION_NEEDED) {
                if (
                    tdxStatus == TCBStatus.TCB_OUT_OF_DATE
                        || tdxStatus == TCBStatus.TCB_OUT_OF_DATE_CONFIGURATION_NEEDED
                ) {
                    configurationNeeded = _tcbConfigurationNeeded(sgxStatus) || _tcbConfigurationNeeded(tdxStatus);
                    TCBLevelsObj memory latestTcbLevel = tcbLevels[0];

                    if (teeTcbSvn2[1] == 0) {
                        if (
                            uint8(teeTcbSvn2[0]) >= latestTcbLevel.tdxComponentCpuSvns[0]
                                && uint8(teeTcbSvn2[2]) >= latestTcbLevel.tdxComponentCpuSvns[2]
                        ) {
                            relaunchAdvised = true;
                        }
                    } else {
                        TDXModuleIdentity memory matchingModuleIdentity;
                        (success, matchingModuleIdentity) =
                            findTdxModuleIdentity(tdxModuleIdentities, uint8(teeTcbSvn2[1]));
                        if (!success) {
                            return
                                (false, "Failed to find matching TDX Module Identity for relaunch check", false, false);
                        }

                        TDXModuleTCBLevelsObj memory latestTdxModuleTcbLevel = matchingModuleIdentity.tcbLevels[0];
                        if (
                            uint8(teeTcbSvn2[0]) >= latestTdxModuleTcbLevel.isvsvn
                                && uint8(teeTcbSvn2[2]) >= latestTcbLevel.tdxComponentCpuSvns[2]
                        ) {
                            relaunchAdvised = true;
                        }
                    }
                }
            }
        }
    }

    function _tcbConfigurationNeeded(TCBStatus tcbStatus) private pure returns (bool) {
        return tcbStatus == TCBStatus.TCB_CONFIGURATION_NEEDED
            || tcbStatus == TCBStatus.TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED
            || tcbStatus == TCBStatus.TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
    }
}
