//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

abstract contract FeeManagerBase is Pausable {
    uint16 constant MAX_BP = 10_000;

    /// @dev this is the amount of gas configured once upon deployment
    /// @dev allocated for ETH payments and refunds
    uint16 immutable REFUND_GAS_OFFSET;

    uint16 _feeBP; // the percentage of gas fee in basis point;

    // 1356a63b
    error BP_Not_Valid();
    // 1a72054d
    error Insuccifient_Funds();
    // c40a532b
    error Withdrawal_Failed();

    constructor(uint16 offset) {
        REFUND_GAS_OFFSET = offset;
    }

    /// @dev access-controlled
    function setBp(uint16 _newBp) public virtual whenNotPaused {
        if (_newBp > MAX_BP) {
            revert BP_Not_Valid();
        }
        _feeBP = _newBp;
    }

    /// @dev access-controlled
    function pause() public virtual {
        if (paused()) {
            _unpause();
        } else {
            _pause();
        }
    }

    function getBp() public view returns (uint16) {
        return _feeBP;
    }

    function withdraw(address beneficiary, uint256 amount) public virtual {
        if (amount > address(this).balance) {
            revert Insuccifient_Funds();
        }

        _refund(beneficiary, amount);
    }

    modifier collectFee() {
        uint256 txFee;
        if (!paused() && _feeBP > 0) {
            uint256 gasBefore = gasleft();
            _;
            uint256 gasAfter = gasleft();
            txFee = ((gasBefore - gasAfter + REFUND_GAS_OFFSET) * tx.gasprice * _feeBP) / MAX_BP;
            if (msg.value < txFee) {
                revert Insuccifient_Funds();
            }
        } else {
            _;
        }

        // refund excess
        if (msg.value > 0) {
            uint256 excess = msg.value - txFee;
            if (excess > 0) {
                _refund(msg.sender, excess);
            }
        }
    }

    function _refund(address recipient, uint256 amount) private {
        (bool success,) = recipient.call{value: amount}("");
        if (!success) {
            revert Withdrawal_Failed();
        }
    }
}
