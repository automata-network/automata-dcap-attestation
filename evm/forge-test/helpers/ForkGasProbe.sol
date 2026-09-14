// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// Test-only local benchmark. Calls real verifiers twice within one transaction
/// to observe first-access versus warmed account/storage costs. Never deployed
/// as part of the production release, and never substitutes a verifier.
contract ForkGasProbe {
    event Sample(uint256 indexed index, uint256 callGas, bytes32 outputHash);
    receive() external payable {}

    function probe(address target, bytes calldata input) external payable {
        require(msg.value % 2 == 0, "equal payments required");
        bytes32 first;
        for (uint256 i; i < 2; ++i) {
            uint256 beforeGas = gasleft();
            (bool ok, bytes memory result) = target.call{value: msg.value / 2}(input);
            uint256 spent = beforeGas - gasleft();
            require(ok, "target reverted");
            (bool accepted, bytes memory output) = abi.decode(result, (bool, bytes));
            require(accepted, "target rejected");
            bytes32 hash = keccak256(output);
            if (i == 0) first = hash;
            else require(hash == first, "outputs differ");
            emit Sample(i, spent, hash);
        }
    }
}
