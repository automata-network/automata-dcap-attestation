// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../../contracts/verifiers/V3QuoteVerifier.sol";

contract DeployV3 is Script {
    uint256 deployerKey = uint256(vm.envBytes32("PRIVATE_KEY"));
    address router = vm.envAddress("PCCS_ROUTER");

    function run() public {
        vm.broadcast(deployerKey);
        V3QuoteVerifier verifier = new V3QuoteVerifier(router);
        console.log("V3QuoteVerifier deployed at ", address(verifier));
    }
}
