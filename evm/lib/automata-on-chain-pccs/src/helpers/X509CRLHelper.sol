// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Asn1Decode, NodePtr} from "../utils/Asn1Decode.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";
import {DateTimeUtils} from "../utils/DateTimeUtils.sol";

/**
 * @title Solidity Structure representing X509 CRL
 * @notice This is a simplified structure of a DER-decoded X509 CRL
 */
struct X509CRLObj {
    uint256 serialNumber;
    string issuerCommonName;
    uint256 validityNotBefore;
    uint256 validityNotAfter;
    uint256[] serialNumbersRevoked;
    // for signature verification in the cert chain
    bytes signature;
    bytes tbs;
}

/**
 * @title X509 CRL Helper Contract
 * @notice This is a standalone contract that can be used by off-chain applications and smart contracts
 * to parse DER-encoded CRLs.
 * @dev This parser is only valid for ECDSA signature algorithm and p256 key algorithm.
 */
contract X509CRLHelper {
    using Asn1Decode for bytes;
    using NodePtr for uint256;
    using BytesUtils for bytes;

    // 2.5.29.20
    bytes constant CRL_NUMBER_OID = hex"551d14";

    /// =================================================================================
    /// USE THE GETTERS BELOW IF YOU DON'T WANT TO PARSE THE ENTIRE X509 CRL
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
        serialNum = _parseSerialNumber(der.bytesAt(tbsPtr));
    }

    function getIssuerCommonName(bytes calldata der) external pure returns (string memory issuerCommonName) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        issuerCommonName = _getCommonName(der, der.firstChildOf(tbsPtr));
    }

    function getCrlValidity(bytes calldata der) external pure returns (uint256 validityNotBefore, uint256 validityNotAfter) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        (validityNotBefore, validityNotAfter) = _getValidity(der, tbsPtr);
    }

    function serialNumberIsRevoked(uint256 serialNumber, bytes calldata der) external pure returns (bool revoked) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        uint256[] memory ret = _getRevokedSerialNumbers(der, tbsPtr, true, serialNumber);
        revoked = ret[0] == serialNumber;
    }

    /// x509 CRL generally contain a sequence of elements in the following order:
    /// 1. tbs
    /// - 1a. serial number
    /// - 1b. signature algorithm
    /// - 1c. issuer
    /// - - 1c(a). common name
    /// - - 1c(b). organization name
    /// - - 1c(c). locality name
    /// - - 1c(d). state or province name
    /// - - 1c(e). country name
    /// - 1d. not before
    /// - 1e. not after
    /// - 1f. revoked certificates
    /// - - A list consists of revoked serial numbers and reasons.
    /// - 1g. CRL extensions
    /// - - 1g(a) CRL number
    /// - - 1g(b) Authority Key Identifier
    /// 2. Signature Algorithm
    /// 3. Signature
    function parseCRLDER(bytes calldata der) external pure returns (X509CRLObj memory crl) {
        uint256 root = der.root();

        uint256 tbsParentPtr = der.firstChildOf(root);
        crl.tbs = der.allBytesAt(tbsParentPtr);

        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);

        crl.serialNumber = uint256(bytes32(der.bytesAt(tbsPtr)));

        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);

        crl.issuerCommonName = _getCommonName(der, der.firstChildOf(tbsPtr));

        tbsPtr = der.nextSiblingOf(tbsPtr);
        (crl.validityNotBefore, crl.validityNotAfter) = _getValidity(der, tbsPtr);

        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);

        crl.serialNumbersRevoked = _getRevokedSerialNumbers(der, tbsPtr, false, 0);

        // tbs iteration completed
        // now we just need to look for the signature

        uint256 sigPtr = der.nextSiblingOf(tbsParentPtr);
        sigPtr = der.nextSiblingOf(sigPtr);
        crl.signature = _getSignature(der, sigPtr);
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
        uint256 notBeforePtr = validityPtr;
        uint256 notAfterPtr = der.nextSiblingOf(notBeforePtr);
        notBefore = DateTimeUtils.fromDERToTimestamp(der.bytesAt(notBeforePtr));
        notAfter = DateTimeUtils.fromDERToTimestamp(der.bytesAt(notAfterPtr));
    }

    function _getRevokedSerialNumbers(bytes calldata der, uint256 revokedParentPtr, bool breakIfFound, uint256 filter)
        private
        pure
        returns (uint256[] memory serialNumbers)
    {
        uint256 revokedPtr = der.firstChildOf(revokedParentPtr);

        if (der[revokedPtr.ixs()] == 0xA0) {
            uint256 crlExtensionPtr = der.firstChildOf(revokedPtr);
            require(BytesUtils.compareBytes(der.bytesAt(crlExtensionPtr), CRL_NUMBER_OID), "invalid CRL");
        } else {
            bytes memory serials;
            while (revokedPtr.ixl() <= revokedParentPtr.ixl()) {
                uint256 serialPtr = der.firstChildOf(revokedPtr);
                bytes memory serialBytes = der.bytesAt(serialPtr);
                uint256 serialNumber = _parseSerialNumber(serialBytes);
                serials = abi.encodePacked(serials, serialNumber);
                if (breakIfFound && filter == serialNumber) {
                    serialNumbers = new uint256[](1);
                    serialNumbers[0] = filter;
                    return serialNumbers;
                }
                revokedPtr = der.nextSiblingOf(revokedPtr);
            }
            uint256 count = serials.length / 32;
            // ABI encoding format for a dynamic uint256[] value
            serials = abi.encodePacked(abi.encode(0x20), abi.encode(count), serials);
            serialNumbers = new uint256[](count);
            serialNumbers = abi.decode(serials, (uint256[]));
        }
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
