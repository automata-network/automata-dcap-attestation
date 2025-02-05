// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Asn1Decode, NodePtr} from "../utils/Asn1Decode.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";
import {DateTimeUtils} from "../utils/DateTimeUtils.sol";

/**
 * @title Solidity Structure representing X509 Certificates
 * @notice This is a simplified structure of a DER-decoded X509 Certificate
 */
struct X509CertObj {
    uint256 serialNumber;
    string issuerCommonName;
    uint256 validityNotBefore;
    uint256 validityNotAfter;
    string subjectCommonName;
    bytes subjectPublicKey;
    // the extension needs to be parsed further for PCK Certificates
    uint256 extensionPtr;
    // for signature verification in the cert chain
    bytes signature;
    bytes tbs;
}

/**
 * @title X509 Certificates Helper Contract
 * @notice This is a standalone contract that can be used by off-chain applications and smart contracts
 * to parse DER-encoded X509 certificates.
 * @dev This parser is only valid for ECDSA signature algorithm and p256 key algorithm.
 */
contract X509Helper {
    using Asn1Decode for bytes;
    using NodePtr for uint256;
    using BytesUtils for bytes;

    /// =================================================================================
    /// USE THE GETTERS BELOW IF YOU DON'T WANT TO PARSE THE ENTIRE X509 CERTIFICATE
    /// =================================================================================

    function getTbsAndSig(bytes calldata der) external pure returns (bytes memory tbs, bytes memory sig) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 sigPtr = der.nextSiblingOf(tbsParentPtr);
        sigPtr = der.nextSiblingOf(sigPtr);

        tbs = der.allBytesAt(tbsParentPtr);
        sig = _getSignature(der, sigPtr);
    }

    function getSerialNumber(bytes calldata der) external pure returns (uint256 serialNum) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        serialNum = _parseSerialNumber(der.bytesAt(tbsPtr));
    }

    function getIssuerCommonName(bytes calldata der) external pure returns (string memory issuerCommonName) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        issuerCommonName = _getCommonName(der, der.firstChildOf(tbsPtr));
    }

    function getCertValidity(bytes calldata der) external pure returns (uint256 validityNotBefore, uint256 validityNotAfter) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        (validityNotBefore, validityNotAfter) = _getValidity(der, tbsPtr);
    }

    function getSubjectCommonName(bytes calldata der) external pure returns (string memory subjectCommonName) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        subjectCommonName = _getCommonName(der, der.firstChildOf(tbsPtr));
    }

    function getSubjectPublicKey(bytes calldata der) external pure returns (bytes memory pubKey) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        pubKey = _getSubjectPublicKey(der, der.firstChildOf(tbsPtr));
    }

    /// x509 Certificates generally contain a sequence of elements in the following order:
    /// 1. tbs
    /// - 1a. version
    /// - 1b. serial number
    /// - 1c. siganture algorithm
    /// - 1d. issuer
    /// - - 1d(a). common name
    /// - - 1d(b). organization name
    /// - - 1d(c). locality name
    /// - - 1d(d). state or province name
    /// - - 1d(e). country name
    /// - 1e. validity
    /// - - 1e(a) notBefore
    /// - - 1e(b) notAfter
    /// - 1f. subject
    /// - - contains the same set of elements as 1d
    /// - 1g. subject public key info
    /// - - 1g(a). algorithm
    /// - - 1g(b). subject public key
    /// - 1h. Extensions
    /// 2. Signature Algorithm
    /// 3. Signature
    function parseX509DER(bytes calldata der) external pure returns (X509CertObj memory cert) {
        uint256 root = der.root();

        uint256 tbsParentPtr = der.firstChildOf(root);
        cert.tbs = der.allBytesAt(tbsParentPtr);

        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);

        tbsPtr = der.nextSiblingOf(tbsPtr);

        cert.serialNumber = _parseSerialNumber(der.bytesAt(tbsPtr));

        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);

        cert.issuerCommonName = _getCommonName(der, der.firstChildOf(tbsPtr));

        tbsPtr = der.nextSiblingOf(tbsPtr);
        (cert.validityNotBefore, cert.validityNotAfter) = _getValidity(der, tbsPtr);

        tbsPtr = der.nextSiblingOf(tbsPtr);

        cert.subjectCommonName = _getCommonName(der, der.firstChildOf(tbsPtr));

        tbsPtr = der.nextSiblingOf(tbsPtr);
        cert.subjectPublicKey = _getSubjectPublicKey(der, der.firstChildOf(tbsPtr));

        cert.extensionPtr = der.nextSiblingOf(tbsPtr);

        // tbs iteration completed
        // now we just need to look for the signature

        uint256 sigPtr = der.nextSiblingOf(tbsParentPtr);
        sigPtr = der.nextSiblingOf(sigPtr);
        cert.signature = _getSignature(der, sigPtr);
    }

    function _getCommonName(bytes calldata der, uint256 commonNameParentPtr)
        private
        pure
        returns (string memory commonName)
    {
        commonNameParentPtr = der.firstChildOf(commonNameParentPtr);
        commonNameParentPtr = der.firstChildOf(commonNameParentPtr);
        commonNameParentPtr = der.nextSiblingOf(commonNameParentPtr);
        commonName = string(der.bytesAt(commonNameParentPtr));
    }

    function _getValidity(bytes calldata der, uint256 validityPtr)
        private
        pure
        returns (uint256 notBefore, uint256 notAfter)
    {
        uint256 notBeforePtr = der.firstChildOf(validityPtr);
        uint256 notAfterPtr = der.nextSiblingOf(notBeforePtr);
        notBefore = DateTimeUtils.fromDERToTimestamp(der.bytesAt(notBeforePtr));
        notAfter = DateTimeUtils.fromDERToTimestamp(der.bytesAt(notAfterPtr));
    }

    function _getSubjectPublicKey(bytes calldata der, uint256 subjectPublicKeyInfoPtr)
        private
        pure
        returns (bytes memory pubKey)
    {
        subjectPublicKeyInfoPtr = der.nextSiblingOf(subjectPublicKeyInfoPtr);
        pubKey = der.bitstringAt(subjectPublicKeyInfoPtr);
        if (pubKey.length != 65) {
            // TODO: we need to figure out how to handle key with prefix byte 0x02 or 0x03
            revert("compressed public key not supported");
        }
        pubKey = _trimBytes(pubKey, 64);
    }

    function _parseSerialNumber(bytes memory serialBytes) private pure returns (uint256 serial) {
        uint256 shift = 8 * (32 - serialBytes.length);
        serial = uint256(bytes32(serialBytes) >> shift);
    }

    function _getSignature(bytes calldata der, uint256 sigPtr) private pure returns (bytes memory sig) {
        sigPtr = der.rootOfBitStringAt(sigPtr);

        sigPtr = der.firstChildOf(sigPtr);
        bytes memory r = _trimBytes(der.bytesAt(sigPtr), 32);

        sigPtr = der.nextSiblingOf(sigPtr);
        bytes memory s = _trimBytes(der.bytesAt(sigPtr), 32);

        sig = abi.encodePacked(r, s);
    }

    /// @dev remove unnecessary prefix from the input
    function _trimBytes(bytes memory input, uint256 expectedLength) private pure returns (bytes memory output) {
        uint256 n = input.length;
        if (n == expectedLength) {
            output = input;
        } else if (n < expectedLength) {
            output = new bytes(expectedLength);
            uint256 padLength = expectedLength - n;
            for (uint256 i = 0; i < n; i++) {
                output[padLength + i] = input[i];
            }
        } else {
            uint256 lengthDiff = n - expectedLength;
            output = input.substring(lengthDiff, expectedLength);
        }
    }
}
