// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Vm.sol";
import "forge-std/console.sol";

abstract contract Multichain {
    address constant HEVM_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
    Vm constant internalVm = Vm(HEVM_ADDRESS);

    modifier multichain(bool runMultichain) {
        if (runMultichain) {
            string[] memory chains = internalVm.envString("CHAINS", ",");
            for (uint256 i = 0; i < chains.length; i++) {
                string memory chain = chains[i];
                string memory rpcUrl = internalVm.envString(string.concat(chain, "_RPC_URL"));

                // run the fork
                try internalVm.createSelectFork(rpcUrl) {
                    // run the script
                    _;
                } catch {
                    // if the fork fails, skip it
                    console.log("Skipping chain: ", chain);
                }
            }
        } else {
            _;
        }
    }

}