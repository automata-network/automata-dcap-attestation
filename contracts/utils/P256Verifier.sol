// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./BytesUtils.sol";

/**
 * @notice modified from https://github.com/daimo-eth/p256-verifier/
 */
library P256Verifier {
    using BytesUtils for bytes;

    address internal constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    function ecdsaVerify(bytes32 messageHash, bytes memory signature, bytes memory key)
        internal
        view
        returns (bool verified)
    {
        bytes memory args = abi.encode(
            messageHash,
            uint256(bytes32(signature.substring(0, 32))),
            uint256(bytes32(signature.substring(32, 32))),
            uint256(bytes32(key.substring(0, 32))),
            uint256(bytes32(key.substring(32, 32)))
        );
        (bool success, bytes memory ret) = P256_VERIFIER.staticcall(args);
        assert(success); // never reverts, always returns 0 or 1

        verified = abi.decode(ret, (uint256)) == 1;
    }
}
