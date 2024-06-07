// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BytesUtils, P256Verifier} from "../utils/P256Verifier.sol";
import {PCKCertTCB} from "../types/CommonStruct.sol";

import {LibString} from "solady/utils/LibString.sol";
import {Base64} from "solady/utils/Base64.sol";
import {PCKHelper, X509CertObj} from "@automata-network/on-chain-pccs/helper/PCKHelper.sol";
import {X509CRLHelper} from "@automata-network/on-chain-pccs/helper/X509CRLHelper.sol";
import {PcsDao, CA} from "@automata-network/on-chain-pccs/dao/PcsDao.sol";

abstract contract X509ChainBase {
    using BytesUtils for bytes;

    string constant PLATFORM_ISSUER_NAME = "Intel SGX PCK Platform CA";
    string constant PROCESSOR_ISSUER_NAME = "Intel SGX PCK Processor CA";

    // keccak256(hex"0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394")
    // the uncompressed (0x04) prefix is not included in the pubkey pre-image
    bytes32 constant ROOTCA_PUBKEY_HASH = 0x89f72d7c488e5b53a77c23ebcb36970ef7eb5bcf6658e9b8292cfbe4703a8473;

    // === PEM PARSER CONSTANTS ===
    string constant X509_HEADER = "-----BEGIN CERTIFICATE-----";
    string constant X509_FOOTER = "-----END CERTIFICATE-----";
    uint256 constant X509_HEADER_LENGTH = 27;
    uint256 constant X509_FOOTER_LENGTH = 25;

    function splitCertificateChain(bytes memory pemChain, uint256 size)
        internal
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
            (success, certs[i], increment) = _removeHeadersAndFooters(input);
            certs[i] = Base64.decode(string(certs[i]));

            if (!success) {
                return (false, certs);
            }

            index += increment;
        }

        success = true;
    }

    function verifyCertChain(address pcsDaoAddr, address crlHelperAddr, X509CertObj[] memory certs)
        internal
        view
        returns (bool)
    {
        PcsDao pcsDao = PcsDao(pcsDaoAddr);
        X509CRLHelper crlHelper = X509CRLHelper(crlHelperAddr);
        uint256 n = certs.length;
        bool certRevoked;
        bool certNotExpired;
        bool verified;
        bool certChainCanBeTrusted;
        for (uint256 i = 0; i < n; i++) {
            X509CertObj memory issuer;
            if (i == n - 1) {
                // rootCA
                issuer = certs[i];
            } else {
                issuer = certs[i + 1];
                bytes memory crl;
                if (i == n - 2) {
                    (, crl) = pcsDao.getCertificateById(CA.ROOT);
                } else if (i == 0) {
                    string memory issuerName = certs[i].issuerCommonName;
                    if (LibString.eq(issuerName, PLATFORM_ISSUER_NAME)) {
                        (, crl) = pcsDao.getCertificateById(CA.PLATFORM);
                    } else if (LibString.eq(issuerName, PROCESSOR_ISSUER_NAME)) {
                        (, crl) = pcsDao.getCertificateById(CA.PROCESSOR);
                    } else {
                        return false;
                    }
                }
                if (crl.length > 0) {
                    certRevoked = crlHelper.serialNumberIsRevoked(certs[i].serialNumber, crl);
                }
                if (certRevoked) {
                    break;
                }
            }

            certNotExpired = block.timestamp > certs[i].validityNotBefore && block.timestamp < certs[i].validityNotAfter;
            if (!certNotExpired) {
                break;
            }

            {
                verified = P256Verifier.ecdsaVerify(sha256(certs[i].tbs), certs[i].signature, issuer.subjectPublicKey);
                if (!verified) {
                    break;
                }
            }

            bytes32 issuerPubKeyHash = keccak256(issuer.subjectPublicKey);

            if (issuerPubKeyHash == ROOTCA_PUBKEY_HASH) {
                certChainCanBeTrusted = true;
                break;
            }
        }
        return !certRevoked && certNotExpired && verified && certChainCanBeTrusted;
    }

    function _removeHeadersAndFooters(string memory pemData)
        private
        pure
        returns (bool success, bytes memory extracted, uint256 endIndex)
    {
        // Check if the input contains the "BEGIN" and "END" headers
        uint256 beginPos = LibString.indexOf(pemData, X509_HEADER);
        uint256 endPos = LibString.indexOf(pemData, X509_FOOTER);

        bool headerFound = beginPos != LibString.NOT_FOUND;
        bool footerFound = endPos != LibString.NOT_FOUND;

        if (!headerFound || !footerFound) {
            return (false, extracted, endIndex);
        }

        // Extract the content between the headers
        uint256 contentStart = beginPos + X509_HEADER_LENGTH;

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
        return (true, contentBytes, endPos + X509_FOOTER_LENGTH);
    }
}
