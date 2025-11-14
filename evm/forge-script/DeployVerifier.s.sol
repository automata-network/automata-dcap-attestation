// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "./utils/P256Configuration.sol";
import "./utils/DeploymentConfig.sol";
import "./utils/Salt.sol";
import "./utils/Multichain.sol";
import "../contracts/verifiers/V3QuoteVerifier.sol";
import "../contracts/verifiers/V4QuoteVerifier.sol";
import "../contracts/verifiers/V5QuoteVerifier.sol";
import "../contracts/AutomataDcapAttestationFee.sol";
import "../contracts/PCCSRouter.sol";

contract DeployVerifier is DeploymentConfig, P256Configuration, Multichain {
    address owner = vm.envAddress("OWNER");
    uint16 version;

    function run() public override multichain {
        version = uint16(vm.envUint("QUOTE_VERIFIER_VERSION"));

        // Read router address after multichain fork is active
        address router = readContractAddress(ProjectType.DCAP, "PCCSRouter");
        bytes32 salt = verifierSalt(version);
        address p256Verifier = simulateVerify();

        vm.startBroadcast(owner);
        address verifier = deployVerifierForVersion(version, salt, p256Verifier, router);
        vm.stopBroadcast();

        string memory contractName = string.concat("V", vm.toString(version), "QuoteVerifier");
        console.log(contractName, " deployed at ", verifier);
        writeToJson(contractName, verifier);
    }

    function overrideVerifier(address p256Verifier) public {
        version = uint16(vm.envUint("QUOTE_VERIFIER_VERSION"));

        address router = readContractAddress(ProjectType.DCAP, "PCCSRouter");
        bytes32 salt = verifierSalt(version);

        vm.startBroadcast(owner);
        address verifier = deployVerifierForVersion(version, salt, p256Verifier, router);
        vm.stopBroadcast();

        string memory contractName = string.concat("V", vm.toString(version), "QuoteVerifier");
        console.log(contractName, " deployed at ", verifier);
        writeToJson(contractName, verifier);
    }

    function deployVerifierForVersion(uint16 _version, bytes32 salt, address p256Verifier, address router)
        internal
        returns (address verifierAddr)
    {
        if (_version == 3) {
            V3QuoteVerifier verifier = new V3QuoteVerifier{salt: salt}(p256Verifier, router);
            verifierAddr = address(verifier);
        } else if (_version == 4) {
            V4QuoteVerifier verifier = new V4QuoteVerifier{salt: salt}(p256Verifier, router);
            verifierAddr = address(verifier);
        } else if (_version == 5) {
            V5QuoteVerifier verifier = new V5QuoteVerifier{salt: salt}(p256Verifier, router);
            verifierAddr = address(verifier);
        } else {
            revert(string.concat("Unsupported quote verifier version: ", vm.toString(_version)));
        }

        PCCSRouter(router).setAuthorized(verifierAddr, true);

        address dcap = readContractAddress(ProjectType.DCAP, "AutomataDcapAttestationFee");
        AutomataDcapAttestationFee(dcap).setQuoteVerifier(verifierAddr);
    }
}
