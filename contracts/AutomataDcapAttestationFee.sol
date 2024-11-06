//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AttestationEntrypointBase.sol";
import "./bases/FeeManagerBase.sol";

contract AutomataDcapAttestationFee is FeeManagerBase, AttestationEntrypointBase {
    constructor(uint16 refundOffset) FeeManagerBase(refundOffset) {}
    
    function setBp(uint16 _newBp) public override onlyOwner {
        super.setBp(_newBp);
    }

    function withdraw(address beneficiary, uint256 amount) public override onlyOwner {
        super.withdraw(beneficiary, amount);
    }

    function verifyAndAttestOnChain(bytes calldata rawQuote)
        external
        payable
        collectFee
        returns (bool success, bytes memory output)
    {
        (success, output) = _verifyAndAttestOnChain(rawQuote);
    }

    function verifyAndAttestWithZKProof(bytes calldata output, bytes calldata proofBytes)
        external
        payable
        collectFee
        returns (bool success, bytes memory verifiedOutput)
    {
        (success, verifiedOutput) = _verifyAndAttestWithZKProof(output, proofBytes);
    }
}
