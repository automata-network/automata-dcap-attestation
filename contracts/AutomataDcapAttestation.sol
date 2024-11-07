//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AttestationEntrypointBase.sol";

contract AutomataDcapAttestation is AttestationEntrypointBase {
    function verifyAndAttestOnChain(bytes calldata rawQuote)
        external
        view
        returns (bool success, bytes memory output)
    {
        (success, output) = _verifyAndAttestOnChain(rawQuote);
    }

    function verifyAndAttestWithZKProof(bytes calldata output, bytes calldata proofBytes)
        external
        view
        returns (bool success, bytes memory verifiedOutput)
    {
        (success, verifiedOutput) = _verifyAndAttestWithZKProof(output, proofBytes);
    }
}
