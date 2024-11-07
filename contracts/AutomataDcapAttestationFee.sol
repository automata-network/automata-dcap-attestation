//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AttestationEntrypointBase.sol";
import "./bases/FeeManagerBase.sol";

contract AutomataDcapAttestationFee is FeeManagerBase, AttestationEntrypointBase {
    error SimulationComplete(bool success, uint256 gas);

    constructor(uint16 refundOffset) FeeManagerBase(refundOffset) {}

    function pause() public override onlyOwner {
        super.pause();
    }

    function setBp(uint16 _newBp) public override onlyOwner {
        super.setBp(_newBp);
    }

    function withdraw(address beneficiary, uint256 amount) public override onlyOwner {
        super.withdraw(beneficiary, amount);
    }

    function simulateVerifyAndAttestOnChain(bytes calldata rawQuote) external view {
        uint256 a = gasleft();
        (bool success,) = _verifyAndAttestOnChain(rawQuote);
        uint256 b = gasleft();
        revert SimulationComplete(success, a - b);
    }

    function simulateVerifyAndAttestWithZkProof(bytes calldata output, bytes calldata proofBytes) external view {
        uint256 a = gasleft();
        (bool success,) = _verifyAndAttestWithZKProof(output, proofBytes);
        uint256 b = gasleft();
        revert SimulationComplete(success, a - b);
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
