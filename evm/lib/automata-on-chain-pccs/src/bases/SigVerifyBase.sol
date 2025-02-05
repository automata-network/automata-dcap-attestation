// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BytesUtils} from "../utils/BytesUtils.sol";
import {P256Verifier} from "../utils/P256Verifier.sol";

interface IX509 {
    function getSubjectPublicKey(bytes memory der) external pure returns (bytes memory pubKey);
}

/**
 * @title Signature verification base contract
 * @notice It can be extended by any contracts that required ECDSA verification
 */

abstract contract SigVerifyBase is P256Verifier {
    address public x509;

    using BytesUtils for bytes;

    constructor(address _p256Verifier, address _x509helper) P256Verifier(_p256Verifier) {
        x509 = _x509helper;
    }

    function verifySignature(bytes32 digest, bytes memory signature, bytes memory signingCertBlob)
        internal
        view
        returns (bool verified)
    {
        if (signature.length != 64) {
            return false;
        }

        bytes memory pubKey = IX509(x509).getSubjectPublicKey(signingCertBlob);
        if (pubKey.length != 64) {
            return false;
        }

        verified = ecdsaVerify(digest, signature, pubKey);
    }
}
