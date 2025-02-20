// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "../utils/P256Configuration.sol";
import "../../contracts/verifiers/V3QuoteVerifier.sol";

contract DeployV3 is P256Configuration {
    uint256 deployerKey = uint256(vm.envBytes32("PRIVATE_KEY"));
    address router = vm.envAddress("PCCS_ROUTER");

    function run() public override {
        vm.startBroadcast(deployerKey);
        V3QuoteVerifier verifier = new V3QuoteVerifier(simulateVerify(), router);
        vm.stopBroadcast();
        console.log("V3QuoteVerifier deployed at ", address(verifier));
    }

    function overrideVerifier(address p256Verifier) public {
        vm.startBroadcast(deployerKey);
        V3QuoteVerifier verifier = new V3QuoteVerifier(p256Verifier, router);
        vm.stopBroadcast();
        console.log("V3QuoteVerifier deployed at ", address(verifier));
    }
}
