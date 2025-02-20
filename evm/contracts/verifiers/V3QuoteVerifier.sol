//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../bases/QuoteVerifierBase.sol";
import "../types/V3Structs.sol";
import "../bases/tcb/TCBInfoV2Base.sol";

/**
 * @title Automata DCAP QuoteV3 Verifier
 */

contract V3QuoteVerifier is QuoteVerifierBase, TCBInfoV2Base {
    constructor(address _ecdsaVerifier, address _router) QuoteVerifierBase(_router, 3) P256Verifier(_ecdsaVerifier) {}

    function verifyZkOutput(bytes calldata outputBytes)
        external
        view
        override
        returns (bool success, bytes memory output)
    {
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
        V3Quote memory quote;
        bytes memory rawQeReport;
        (success, reason, quote, rawQeReport) = _parseV3Quote(header, rawQuote);
        if (!success) {
            return (false, bytes(reason));
        }

        (success, output) = _verifyQuote(
            quote, rawQuote[0:HEADER_LENGTH], rawQuote[HEADER_LENGTH:HEADER_LENGTH + ENCLAVE_REPORT_LENGTH], rawQeReport
        );
    }

    function _parseV3Quote(Header calldata header, bytes calldata quote)
        private
        view
        returns (bool success, string memory reason, V3Quote memory parsed, bytes memory rawQeReport)
    {
        (success, reason) = validateHeader(header, quote.length, header.teeType == SGX_TEE);
        if (!success) {
            return (success, reason, parsed, rawQeReport);
        }

        // now that we are able to confirm that the provided quote is a valid V3 SGX quote
        // based on information found in the header
        // we continue parsing the remainder of the quote

        // parse the local isv report
        EnclaveReport memory localReport;
        uint256 offset = HEADER_LENGTH + ENCLAVE_REPORT_LENGTH;
        (success, localReport) = parseEnclaveReport(quote[HEADER_LENGTH:offset]);
        if (!success) {
            return (false, "failed to parse local isv report", parsed, rawQeReport);
        }

        // check authData length
        uint256 localAuthDataSize = BELE.leBytesToBeUint(quote[offset:offset + 4]);
        offset += 4;
        if (quote.length - offset < localAuthDataSize) {
            return (false, "quote length is incorrect", parsed, rawQeReport);
        }

        // at this point, we have verified the length of the entire quote to be correct
        // parse authData
        ECDSAQuoteV3AuthData memory authData;
        (success, authData, rawQeReport) = _parseAuthData(quote[offset:offset + localAuthDataSize]);
        if (!success) {
            return (false, "failed to parse authdata", parsed, rawQeReport);
        }

        success = true;
        parsed = V3Quote({header: header, localEnclaveReport: localReport, authData: authData});
    }

    function _verifyQuote(V3Quote memory quote, bytes memory rawHeader, bytes memory rawBody, bytes memory rawQeReport)
        private
        view
        returns (bool success, bytes memory serialized)
    {
        // Step 0: Check QE Report Data
        success = verifyQeReportData(
            quote.authData.qeReport.reportData, quote.authData.ecdsaAttestationKey, quote.authData.qeAuthData.data
        );
        if (!success) {
            return (success, bytes("Invalid QEReport data"));
        }

        // Step 1: Fetch QEIdentity to validate TCB of the QE
        EnclaveIdTcbStatus qeTcbStatus;
        EnclaveReport memory qeReport = quote.authData.qeReport;
        (success, qeTcbStatus) = fetchQeIdentityAndCheckQeReport(EnclaveId.QE, qeReport);

        if (!success || qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED) {
            return (success, bytes("Verification failed by QEIdentity check"));
        }

        // Step 2: Fetch FMSPC TCB then get TCBStatus
        X509CertObj[] memory parsedCerts = quote.authData.certification.pck.pckChain;
        PCKCertTCB memory pckTcb = quote.authData.certification.pck.pckExtension;
        (bool tcbValid, TCBLevelsObj[] memory tcbLevels) = pccsRouter.getFmspcTcbV2(bytes6(pckTcb.fmspcBytes));
        if (!tcbValid) {
            return (false, bytes("TCB not found or expired"));
        }
        TCBStatus tcbStatus;
        bool statusFound;
        for (uint256 i = 0; i < tcbLevels.length; i++) {
            (statusFound, tcbStatus) = getSGXTcbStatus(pckTcb, tcbLevels[i]);
            if (statusFound) {
                break;
            }
        }
        if (!statusFound || tcbStatus == TCBStatus.TCB_REVOKED) {
            return (statusFound, bytes("Verificaton failed by TCBInfo check"));
        }

        // Step 3: Converge QEIdentity and FMSPC TCB Status
        tcbStatus = convergeTcbStatusWithQeTcbStatus(qeTcbStatus, tcbStatus);

        // Step 4: verify cert chain
        success = verifyCertChain(pccsRouter, pccsRouter.crlHelperAddr(), parsedCerts);
        if (!success) {
            return (success, bytes("Failed to verify X509 Chain"));
        }

        // Step 5: Signature Verification on local isv report and qereport by PCK
        bytes memory localAttestationData = abi.encodePacked(rawHeader, rawBody);
        success = attestationVerification(
            rawQeReport,
            quote.authData.qeReportSignature,
            parsedCerts[0].subjectPublicKey,
            localAttestationData,
            quote.authData.ecdsa256BitSignature,
            quote.authData.ecdsaAttestationKey
        );
        if (!success) {
            return (success, bytes("Failed to verify attestation and/or qe report signatures"));
        }

        Output memory output = Output({
            quoteVersion: quoteVersion,
            tee: SGX_TEE,
            tcbStatus: tcbStatus,
            fmspcBytes: bytes6(pckTcb.fmspcBytes),
            quoteBody: rawBody,
            advisoryIDs: new string[](0)
        });
        serialized = serializeOutput(output);
    }

    /**
     * [0:64] bytes: ecdsa256BitSignature
     * [64:128] bytes: ecdsaAttestationKey
     * [128:512] bytes: qeReport
     * [512:576] bytes: qeReportSignature
     * [576:578] bytes: qeAuthDataSize (Y)
     * [578:578+Y] bytes: qeAuthData
     * [578+Y:580+Y] bytes: pckCertType
     * NOTE: the calculations below assume pckCertType == 5
     * [580+Y:584+Y] bytes: certSize (Z)
     * [584+Y:584+Y+Z] bytes: certData
     */
    function _parseAuthData(bytes calldata rawAuthData)
        private
        view
        returns (bool success, ECDSAQuoteV3AuthData memory authDataV3, bytes memory rawQeReport)
    {
        authDataV3.ecdsa256BitSignature = rawAuthData[0:64];
        authDataV3.ecdsaAttestationKey = rawAuthData[64:128];
        rawQeReport = rawAuthData[128:512];
        authDataV3.qeReportSignature = rawAuthData[512:576];
        uint16 qeAuthDataSize = uint16(BELE.leBytesToBeUint(rawAuthData[576:578]));
        authDataV3.qeAuthData.parsedDataSize = qeAuthDataSize;
        uint256 offset = 578;
        authDataV3.qeAuthData.data = rawAuthData[offset:offset + qeAuthDataSize];
        offset += qeAuthDataSize;

        uint16 certType = uint16(BELE.leBytesToBeUint(rawAuthData[offset:offset + 2]));

        authDataV3.certification.certType = certType;
        offset += 2;
        uint32 certDataSize = uint32(BELE.leBytesToBeUint(rawAuthData[offset:offset + 4]));
        offset += 4;
        authDataV3.certification.certDataSize = certDataSize;
        bytes memory rawCertData = rawAuthData[offset:offset + certDataSize];

        // parsing complete, now we need to decode some raw data

        (success, authDataV3.qeReport) = parseEnclaveReport(rawQeReport);
        if (!success) {
            return (false, authDataV3, rawQeReport);
        }

        (success, authDataV3.certification.pck) = getPckCollateral(pccsRouter.pckHelperAddr(), certType, rawCertData);
        if (!success) {
            return (false, authDataV3, rawQeReport);
        }
    }
}
