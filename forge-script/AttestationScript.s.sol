// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import "../contracts/AutomataDcapAttestation.sol";

contract AttestationScript is Script {
    uint256 deployerKey = uint256(vm.envBytes32("PRIVATE_KEY"));
    address riscZeroVerifier = vm.envAddress("RISC0_VERIFIER");
    bytes32 riscZeroImageId = vm.envBytes32("DCAP_IMAGE_ID");

    function deployEntrypoint() public {
        vm.startBroadcast(deployerKey);

        AutomataDcapAttestation attestation = new AutomataDcapAttestation();

        console.log("Automata Dcap Attestation deployed at: ", address(attestation));

        vm.stopBroadcast();
    }

    function configVerifier(address verifier) public {
        address attestationAddr = vm.envAddress("DCAP_ATTESTATION");
        vm.broadcast(deployerKey);
        AutomataDcapAttestation(attestationAddr).setQuoteVerifier(verifier);
    }

    function configureZk(uint8 zk, address verifierGateway, bytes32 programId) public {
        address attestationAddr = vm.envAddress("DCAP_ATTESTATION");

        ZkCoProcessorConfig memory config = ZkCoProcessorConfig({
            dcapProgramIdentifier: programId,
            zkVerifier: verifierGateway
        });

        vm.broadcast(deployerKey);
        AutomataDcapAttestation(attestationAddr).setZkConfiguration(ZkCoProcessorType(zk), config);
    }
}
