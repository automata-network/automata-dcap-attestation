//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AttestationEntrypointBase.sol";
import "./bases/FeeManagerBase.sol";

/**
 * @title Automata DCAP Attestation With Fee
 * @notice This contract collects a fee, based on a certain % of transaction fee
 * needed to perform DCAP attestation.
 */
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

    /**
     * @dev may perform staticcall to this method to get an estimated gas consumption
     * for calling verifyAndAttestOnChain()
     * @dev get the verification status and gas cost by performing abi.decode of the
     * revert data (not including the 4-byte error selector) of tuple type (bool, uint256).
     */
    function simulateVerifyAndAttestOnChain(bytes calldata rawQuote) external view {
        uint256 a = gasleft();
        (bool success,) = _verifyAndAttestOnChain(rawQuote);
        uint256 b = gasleft();
        revert SimulationComplete(success, a - b);
    }

    /**
     * @dev may perform staticcall to this method to get an estimated gas consumption
     * for calling verifyAndAttestWithZKProof()
     * @dev get the verification status and gas cost by performing abi.decode of the
     * revert data (not including the 4-byte error selector) of tuple type (bool, uint256).
     */
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
