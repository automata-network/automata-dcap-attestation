// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../../contracts/verifiers/V4QuoteVerifier.sol";

contract DeployV4 is Script {
    uint256 deployerKey = uint256(vm.envBytes32("PRIVATE_KEY"));
    address router = vm.envAddress("PCCS_ROUTER");

    function run() public {
        vm.broadcast(deployerKey);
        V4QuoteVerifier verifier = new V4QuoteVerifier(router);
        console.log("V4QuoteVerifier deployed at ", address(verifier));
    }
}
