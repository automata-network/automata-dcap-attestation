// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import {console2} from "forge-std/console2.sol";
import "../contracts/PCCSRouter.sol";
import "./utils/Salt.sol";
import "./utils/DeploymentConfig.sol";

contract DeployRouter is DeploymentConfig {

    address enclaveIdDaoAddr = readContractAddress(ProjectType.PCCS, "AutomataEnclaveIdentityDao");
    address enclaveIdHelperAddr = readContractAddress(ProjectType.PCCS, "EnclaveIdentityHelper");
    address pckHelperAddr = readContractAddress(ProjectType.PCCS, "PCKHelper");
    address tcbDaoAddr = readContractAddress(ProjectType.PCCS, "AutomataFmspcTcbDao");
    address tcbHelperAddr = readContractAddress(ProjectType.PCCS, "FmspcTcbHelper");
    address crlHelperAddr = readContractAddress(ProjectType.PCCS, "X509CRLHelper");
    address pcsDaoAddr = readContractAddress(ProjectType.PCCS, "AutomataPcsDao");
    address pckDaoAddr = readContractAddress(ProjectType.PCCS, "AutomataPckDao");

    address owner = vm.envAddress("OWNER");

    function run() public checkPccsHasDeployed {
        vm.startBroadcast(owner);

        PCCSRouter router = new PCCSRouter{salt: PCCS_ROUTER_SALT}(
            owner, enclaveIdDaoAddr, tcbDaoAddr, pcsDaoAddr, pckDaoAddr, pckHelperAddr, crlHelperAddr, tcbHelperAddr
        );
        console2.log("Deployed PCCSRouter to", address(router));
        writeToJson("PCCSRouter", address(router));

        vm.stopBroadcast();
    }

    function updateConfig() public {
        vm.startBroadcast(owner);

        PCCSRouter router = PCCSRouter(readContractAddress(ProjectType.DCAP, "PCCSRouter"));
        router.setConfig(
            enclaveIdDaoAddr, tcbDaoAddr, pcsDaoAddr, pckDaoAddr, pckHelperAddr, crlHelperAddr, tcbHelperAddr
        );

        vm.stopBroadcast();
    }

    function setAuthorizedCaller(address caller, bool authorized) public {
        vm.startBroadcast(owner);

        PCCSRouter router = PCCSRouter(readContractAddress(ProjectType.DCAP, "PCCSRouter"));
        router.setAuthorized(caller, authorized);

        vm.stopBroadcast();
    }
}
