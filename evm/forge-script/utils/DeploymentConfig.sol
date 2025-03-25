// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";

enum ProjectType {
    PCCS,
    DCAP
}

abstract contract DeploymentConfig is Script {

    modifier checkPccsHasDeployed() {
        require(
            vm.exists(
                string.concat(
                    vm.projectRoot(), "/", "deployment", "/", vm.toString(block.chainid), "/", "onchain_pccs.json"
                )
            ),
            "Missing On Chain PCCS Deployment"
        );
        _;
    }

    function readContractAddress(ProjectType project, string memory contractName)
        internal
        view
        returns (address contractAddress)
    {
        string memory dir = string.concat(vm.projectRoot(), "/", "deployment", "/", vm.toString(block.chainid));
        if (!vm.exists(dir)) {
            revert("Deployment does not exist");
        }
        string memory jsonStr;
        if (project == ProjectType.PCCS) {
            jsonStr = vm.readFile(string.concat(dir, "/", "onchain_pccs.json"));
        } else if (project == ProjectType.DCAP) {
            jsonStr = vm.readFile(string.concat(dir, "/", "dcap.json"));
        }
        contractAddress = stdJson.readAddress(jsonStr, string.concat(".", contractName));
    }

    function writeToJson(string memory contractName, address contractAddress) internal {
        string memory deploymentDir =
            string.concat(vm.projectRoot(), "/", "deployment", "/", vm.toString(block.chainid));

        // deployment path
        string memory jsonPath = string.concat(deploymentDir, "/", "dcap.json");

        string memory jsonKey = "deployment key";
        string memory jsonStr = "";
        if (vm.exists(jsonPath)) {
            jsonStr = vm.readFile(jsonPath);
            vm.serializeJson(jsonKey, jsonStr);
        }

        string memory finalJson = vm.serializeAddress(jsonKey, contractName, contractAddress);
        vm.writeJson(finalJson, jsonPath);
    }
}
