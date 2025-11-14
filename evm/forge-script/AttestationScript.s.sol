// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import {console2} from "forge-std/console2.sol";
import "../contracts/AutomataDcapAttestationFee.sol";
import "../contracts/PCCSRouter.sol";

import "./utils/Salt.sol";
import "./utils/DeploymentConfig.sol";
import "./utils/Multichain.sol";

contract AttestationScript is DeploymentConfig, Multichain {

    address owner = vm.envAddress("OWNER");

    function deployEntrypoint() public multichain {
        vm.startBroadcast(owner);

        AutomataDcapAttestationFee attestation = new AutomataDcapAttestationFee{salt: DCAP_ATTESTATION_SALT}(owner);

        console.log("Automata Dcap Attestation deployed at: ", address(attestation));
        writeToJson("AutomataDcapAttestationFee", address(attestation));

        vm.stopBroadcast();
    }

    function configVerifier(uint256 version) public {
        string memory verifierName = string.concat(
            "V",
            vm.toString(version),
            "QuoteVerifier"
        );
        address attestationAddr = readContractAddress(ProjectType.DCAP, "AutomataDcapAttestationFee");
        address quoteVerifier = readContractAddress(ProjectType.DCAP, verifierName);

        vm.startBroadcast(owner);

        AutomataDcapAttestationFee(attestationAddr).setQuoteVerifier(quoteVerifier);

        vm.stopBroadcast();
    }

    function configureZk(uint8 zk, address verifierGateway, bytes32 programId) public {
        address attestationAddr = readContractAddress(ProjectType.DCAP, "AutomataDcapAttestationFee");

        ZkCoProcessorConfig memory config =
            ZkCoProcessorConfig({latestDcapProgramIdentifier: programId, defaultZkVerifier: verifierGateway});

        vm.broadcast(owner);
        AutomataDcapAttestationFee(attestationAddr).setZkConfiguration(ZkCoProcessorType(zk), config);
    }
}
