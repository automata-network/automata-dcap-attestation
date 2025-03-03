// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "../utils/P256Configuration.sol";
import "../utils/Salt.sol";
import "../../contracts/verifiers/V4QuoteVerifier.sol";

contract DeployV4 is P256Configuration {
    uint256 deployerKey = uint256(vm.envBytes32("PRIVATE_KEY"));
    address router = vm.envAddress("PCCS_ROUTER");

    function run() public override {
        vm.startBroadcast(deployerKey);
        V4QuoteVerifier verifier = new V4QuoteVerifier{salt: V4_VERIFIER_SALT}(simulateVerify(), router);
        vm.stopBroadcast();
        console.log("V4QuoteVerifier deployed at ", address(verifier));
    }

    function overrideVerifier(address p256Verifier) public {
        vm.startBroadcast(deployerKey);
        V4QuoteVerifier verifier = new V4QuoteVerifier{salt: V4_VERIFIER_SALT}(p256Verifier, router);
        vm.stopBroadcast();
        console.log("V4QuoteVerifier deployed at ", address(verifier));
    }
}
