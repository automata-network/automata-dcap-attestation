// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "../utils/P256Configuration.sol";
import "../utils/DeploymentConfig.sol";
import "../utils/Salt.sol";
import "../../contracts/verifiers/V5QuoteVerifier.sol";

contract DeployV5 is DeploymentConfig, P256Configuration {
    address owner = vm.envAddress("OWNER");
    address router = readContractAddress(ProjectType.DCAP, "PCCSRouter");
    function run() public override {
        vm.startBroadcast(owner);
        V5QuoteVerifier verifier = new V5QuoteVerifier{salt: V4_VERIFIER_SALT}(simulateVerify(), router);
        vm.stopBroadcast();
        console.log("V5QuoteVerifier deployed at ", address(verifier));
        writeToJson("V5QuoteVerifier", address(verifier));
    }

    function overrideVerifier(address p256Verifier) public {
        vm.startBroadcast(owner);
        V5QuoteVerifier verifier = new V5QuoteVerifier{salt: V4_VERIFIER_SALT}(p256Verifier, router);
        vm.stopBroadcast();
        console.log("V5QuoteVerifier deployed at ", address(verifier));
        writeToJson("V5QuoteVerifier", address(verifier));
    }
}
