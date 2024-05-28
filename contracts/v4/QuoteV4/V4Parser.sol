//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BytesUtils} from "../../utils/BytesUtils.sol";
import {V4Struct} from "./V4Struct.sol";

import {LibString} from "solady/utils/LibString.sol";
import {Base64} from "solady/utils/Base64.sol";

library V4Parser {
    using BytesUtils for bytes;

    string constant HEADER = "-----BEGIN CERTIFICATE-----";
    string constant FOOTER = "-----END CERTIFICATE-----";
    uint256 constant HEADER_LENGTH = 27;
    uint256 constant FOOTER_LENGTH = 25;

    bytes2 constant SUPPORTED_QUOTE_VERSION = 0x0400; // v4
    bytes2 constant SUPPORTED_ATTESTATION_KEY_TYPE = 0x0200; // ECDSA_256_WITH_P256_CURVE
    bytes16 constant VALID_QE_VENDOR_ID = 0x939a7233f79c4ca9940a0db3957f0607;
    uint256 constant ECDSA_SIG_PUBKEY_LENGTH = 64;

    function parseInput(bytes memory quote)
        internal
        pure
        returns (V4Struct.ParsedV4Quote memory parsedQuote, bytes memory quoteDataBytes, bytes memory qeReportBytes)
    {
        bytes memory headerBytes = quote.substring(0, 48);
        parsedQuote.header = parseQuoteHeader(headerBytes);
        bytes memory reportBodyBytes = quote.substring(48, 584);
        parsedQuote.reportBody = parseReportBody(reportBodyBytes);
        uint256 authDataLength = littleEndianDecode(quote.substring(632, 4));
        (parsedQuote.authData, qeReportBytes) = parseQuoteAuthData(quote.substring(636, authDataLength));
        quoteDataBytes = abi.encodePacked(headerBytes, reportBodyBytes);
    }

    function validateParsedInput(V4Struct.ParsedV4Quote memory parsedQuote)
        internal
        pure
        returns (bool success, string memory reason)
    {
        V4Struct.Header memory header = parsedQuote.header;

        if (header.version != SUPPORTED_QUOTE_VERSION) {
            return (false, "!v4 quote");
        }

        if (header.attestationKeyType != SUPPORTED_ATTESTATION_KEY_TYPE) {
            return (false, "unsupported attestation key type");
        }

        if (header.qeVendorId != VALID_QE_VENDOR_ID) {
            return (false, "Not a valid Intel SGX QE Vendor ID");
        }

        if (
            parsedQuote.authData.ecdsa256BitSignature.length != ECDSA_SIG_PUBKEY_LENGTH
                || parsedQuote.authData.ecdsaAttestationKey.length != ECDSA_SIG_PUBKEY_LENGTH
        ) {
            return (false, "Invalid attestation signature and/or pubkey length");
        }
        success = true;
    }

    /// === METHODS BELOW ARE FOR INTERNAL-USE ONLY ===

    function parseQuoteHeader(bytes memory rawHeader) private pure returns (V4Struct.Header memory header) {
        bytes2 version = bytes2(rawHeader.substring(0, 2));
        bytes2 attestationKeyType = bytes2(rawHeader.substring(2, 2));
        bytes4 teeType = bytes4(rawHeader.substring(4, 4));
        bytes16 qeVendorId = bytes16(rawHeader.substring(12, 16));

        header = V4Struct.Header({
            version: version,
            attestationKeyType: attestationKeyType,
            teeType: teeType,
            qeVendorId: qeVendorId,
            userData: bytes20(rawHeader.substring(28, 20)),
            reserved: bytes4(rawHeader.substring(8, 4))
        });
    }

    function parseReportBody(bytes memory reportBytes) private pure returns (V4Struct.ReportBody memory report) {
        report.teeTcbSvn = bytes16(reportBytes.substring(0, 16));
        report.mrSeam = reportBytes.substring(16, 48);
        report.mrsignerSeam = reportBytes.substring(64, 48);
        report.seamAttributes = bytes8(uint64(littleEndianDecode(reportBytes.substring(112, 8))));
        report.tdAttributes = bytes8(uint64(littleEndianDecode(reportBytes.substring(120, 8))));
        report.xFAM = bytes8(uint64(littleEndianDecode(reportBytes.substring(128, 8))));
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

    function parseQuoteAuthData(bytes memory authDataBytes)
        private
        pure
        returns (V4Struct.ECDSAQuoteV4AuthData memory authData, bytes memory qeReportBytes)
    {
        authData.ecdsa256BitSignature = authDataBytes.substring(0, 64);
        authData.ecdsaAttestationKey = authDataBytes.substring(64, 64);
        uint256 certType = uint16(littleEndianDecode(authDataBytes.substring(128, 2)));
        require(certType == 6, "QEReportCertType != 6");
        uint256 certLength = littleEndianDecode(authDataBytes.substring(130, 4));
        (authData.qeReportCertData, qeReportBytes) =
            parseQeReportCertificationData(authDataBytes.substring(134, certLength));
    }

    function parseQeReportCertificationData(bytes memory qeReportCertData)
        private
        pure
        returns (V4Struct.QEReportCertificationData memory qeReportCert, bytes memory qeReportBytes)
    {
        qeReportBytes = qeReportCertData.substring(0, 384);
        qeReportCert.qeReport = parseEnclaveReport(qeReportBytes);
        qeReportCert.qeReportSignature = qeReportCertData.substring(384, 64);
        uint256 authDataSize = littleEndianDecode(qeReportCertData.substring(448, 2));
        qeReportCert.qeAuthData.parsedDataSize = uint16(authDataSize);
        qeReportCert.qeAuthData.data = qeReportCertData.substring(450, authDataSize);
        uint256 offset = 450 + authDataSize;
        qeReportCert.certData.certType = uint16(littleEndianDecode(qeReportCertData.substring(offset, 2)));
        /// same as V3, we are only supporting certType == 5 for now
        require(qeReportCert.certData.certType == 5, "CertType != 5");
        offset += 2;
        uint256 certLength = littleEndianDecode(qeReportCertData.substring(offset, 4));
        qeReportCert.certData.certDataSize = uint32(certLength);
        offset += 4;
        bool success;
        (success, qeReportCert.certData.decodedCertDataArray) =
            splitCertificateChain(qeReportCertData.substring(offset, certLength), 3);
    }

    function parseEnclaveReport(bytes memory rawEnclaveReport)
        internal
        pure
        returns (V4Struct.EnclaveReport memory enclaveReport)
    {
        enclaveReport.cpuSvn = bytes16(rawEnclaveReport.substring(0, 16));
        enclaveReport.miscSelect = bytes4(rawEnclaveReport.substring(16, 4));
        enclaveReport.reserved1 = bytes28(rawEnclaveReport.substring(20, 28));
        enclaveReport.attributes = bytes16(rawEnclaveReport.substring(48, 16));
        enclaveReport.mrEnclave = bytes32(rawEnclaveReport.substring(64, 32));
        enclaveReport.reserved2 = bytes32(rawEnclaveReport.substring(96, 32));
        enclaveReport.mrSigner = bytes32(rawEnclaveReport.substring(128, 32));
        enclaveReport.reserved3 = rawEnclaveReport.substring(160, 96);
        enclaveReport.isvProdId = uint16(littleEndianDecode(rawEnclaveReport.substring(256, 2)));
        enclaveReport.isvSvn = uint16(littleEndianDecode(rawEnclaveReport.substring(258, 2)));
        enclaveReport.reserved4 = rawEnclaveReport.substring(260, 60);
        enclaveReport.reportData = rawEnclaveReport.substring(320, 64);
    }

    /// enclaveReport to bytes for hash calculation.
    /// the only difference between enclaveReport and packedQEReport is the
    /// order of isvProdId and isvSvn. enclaveReport is in little endian, while
    /// in bytes should be in big endian according to Intel spec.
    /// @param enclaveReport enclave report
    /// @return packedQEReport enclave report in bytes
    function packQEReport(V4Struct.EnclaveReport memory enclaveReport)
        internal
        pure
        returns (bytes memory packedQEReport)
    {
        uint16 isvProdIdPackLE = (enclaveReport.isvProdId >> 8) | (enclaveReport.isvProdId << 8);
        uint16 isvSvnPackLE = (enclaveReport.isvSvn >> 8) | (enclaveReport.isvSvn << 8);
        packedQEReport = abi.encodePacked(
            enclaveReport.cpuSvn,
            enclaveReport.miscSelect,
            enclaveReport.reserved1,
            enclaveReport.attributes,
            enclaveReport.mrEnclave,
            enclaveReport.reserved2,
            enclaveReport.mrSigner,
            enclaveReport.reserved3,
            isvProdIdPackLE,
            isvSvnPackLE,
            enclaveReport.reserved4,
            enclaveReport.reportData
        );
    }

    function littleEndianDecode(bytes memory encoded) private pure returns (uint256 decoded) {
        for (uint256 i = 0; i < encoded.length; i++) {
            uint256 digits = uint256(uint8(bytes1(encoded[i])));
            uint256 upperDigit = digits / 16;
            uint256 lowerDigit = digits % 16;

            uint256 acc = lowerDigit * (16 ** (2 * i));
            acc += upperDigit * (16 ** ((2 * i) + 1));

            decoded += acc;
        }
    }

    function splitCertificateChain(bytes memory pemChain, uint256 size)
        private
        pure
        returns (bool success, bytes[] memory certs)
    {
        certs = new bytes[](size);
        string memory pemChainStr = string(pemChain);

        uint256 index = 0;
        uint256 len = pemChain.length;

        for (uint256 i = 0; i < size; i++) {
            string memory input;
            if (i > 0) {
                input = LibString.slice(pemChainStr, index, index + len);
            } else {
                input = pemChainStr;
            }
            uint256 increment;
            (success, certs[i], increment) = removeHeadersAndFooters(input);
            certs[i] = Base64.decode(string(certs[i]));

            if (!success) {
                return (false, certs);
            }

            index += increment;
        }

        success = true;
    }

    function removeHeadersAndFooters(string memory pemData)
        private
        pure
        returns (bool success, bytes memory extracted, uint256 endIndex)
    {
        // Check if the input contains the "BEGIN" and "END" headers
        uint256 beginPos = LibString.indexOf(pemData, HEADER);
        uint256 endPos = LibString.indexOf(pemData, FOOTER);

        bool headerFound = beginPos != LibString.NOT_FOUND;
        bool footerFound = endPos != LibString.NOT_FOUND;

        if (!headerFound || !footerFound) {
            return (false, extracted, endIndex);
        }

        // Extract the content between the headers
        uint256 contentStart = beginPos + HEADER_LENGTH;

        // Extract and return the content
        bytes memory contentBytes;

        // do not include newline
        bytes memory delimiter = hex"0a";
        string memory contentSlice = LibString.slice(pemData, contentStart, endPos);
        string[] memory split = LibString.split(contentSlice, string(delimiter));
        string memory contentStr;

        for (uint256 i = 0; i < split.length; i++) {
            contentStr = LibString.concat(contentStr, split[i]);
        }

        contentBytes = bytes(contentStr);
        return (true, contentBytes, endPos + FOOTER_LENGTH);
    }
}
