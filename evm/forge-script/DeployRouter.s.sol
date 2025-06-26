// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import {console2} from "forge-std/console2.sol";
import {AutomataDaoStorage} from "@automata-network/on-chain-pccs/automata_pccs/shared/AutomataDaoStorage.sol";

import "../contracts/PCCSRouter.sol";
import "./utils/Salt.sol";
import "./utils/DeploymentConfig.sol";
import "./utils/Multichain.sol";

contract DeployRouter is DeploymentConfig, Multichain {

    address enclaveIdDaoAddr = readContractAddress(ProjectType.PCCS, "AutomataEnclaveIdentityDao");
    address enclaveIdHelperAddr = readContractAddress(ProjectType.PCCS, "EnclaveIdentityHelper");
    address pckHelperAddr = readContractAddress(ProjectType.PCCS, "PCKHelper");
    address tcbDaoAddr = readContractAddress(ProjectType.PCCS, "AutomataFmspcTcbDao");
    address tcbHelperAddr = readContractAddress(ProjectType.PCCS, "FmspcTcbHelper");
    address crlHelperAddr = readContractAddress(ProjectType.PCCS, "X509CRLHelper");
    address pcsDaoAddr = readContractAddress(ProjectType.PCCS, "AutomataPcsDao");
    address pckDaoAddr = readContractAddress(ProjectType.PCCS, "AutomataPckDao");
    address tcbEvalDaoAddr = readContractAddress(ProjectType.PCCS, "AutomataTcbEvalDao");

    address owner = vm.envAddress("OWNER");

    bool useMultichain = vm.envBool("MULTICHAIN");

    function run() public checkPccsHasDeployed {
        vm.startBroadcast(owner);

        PCCSRouter router = new PCCSRouter{salt: PCCS_ROUTER_SALT}(
            owner, enclaveIdDaoAddr, tcbDaoAddr, tcbEvalDaoAddr, pcsDaoAddr, pckDaoAddr, pckHelperAddr, crlHelperAddr, tcbHelperAddr
        );
        console2.log("Deployed PCCSRouter to", address(router));
        writeToJson("PCCSRouter", address(router));

        vm.stopBroadcast();
    }

    function updateConfig() public {
        vm.startBroadcast(owner);

        PCCSRouter router = PCCSRouter(readContractAddress(ProjectType.DCAP, "PCCSRouter"));
        router.setConfig(
            enclaveIdDaoAddr, tcbDaoAddr, tcbEvalDaoAddr, pcsDaoAddr, pckDaoAddr, pckHelperAddr, crlHelperAddr, tcbHelperAddr
        );

        vm.stopBroadcast();
    }

    function updateVersionedDaoConfig(
        uint32 tcbEvaluataionDataNumber
    ) public {
        PCCSRouter router = PCCSRouter(readContractAddress(ProjectType.DCAP, "PCCSRouter"));
        address qeIdDaoAddr = readVersionedContractAddress(
            "AutomataEnclaveIdentityDaoVersioned",
            tcbEvaluataionDataNumber
        );
        address fmspcTcbDaoAddr = readVersionedContractAddress(
            "AutomataFmspcTcbDaoVersioned",
            tcbEvaluataionDataNumber
        );

        bool tcbEvalCheck = tcbEvaluataionDataNumber == IVersionedDao(fmspcTcbDaoAddr).TCB_EVALUATION_NUMBER()
            && tcbEvaluataionDataNumber == IVersionedDao(qeIdDaoAddr).TCB_EVALUATION_NUMBER();
        
        require(tcbEvalCheck, "TCB Evaluation Data Number Mismatch");

        vm.startBroadcast(owner);

        router.setQeIdDaoVersionedAddr(tcbEvaluataionDataNumber, qeIdDaoAddr);
        router.setFmspcTcbDaoVersionedAddr(tcbEvaluataionDataNumber, fmspcTcbDaoAddr);

        vm.stopBroadcast();
    }

    function setAuthorizedCaller(address caller, bool authorized) public {
        vm.startBroadcast(owner);

        PCCSRouter router = PCCSRouter(readContractAddress(ProjectType.DCAP, "PCCSRouter"));
        router.setAuthorized(caller, authorized);

        vm.stopBroadcast();
    }

    function toggleRestriction(bool enable) public {
        PCCSRouter router = PCCSRouter(readContractAddress(ProjectType.DCAP, "PCCSRouter"));

        vm.broadcast(owner);
        if (enable) {
            router.enableCallerRestriction();
        } else {
            router.disableCallerRestriction();
        }
    }

    function grantAccessToStorage() public multichain(useMultichain) {
        vm.startBroadcast(owner);

        console.log("Checking PCCSRouter access to AutomataDaoStorage on chain: ", block.chainid);

        PCCSRouter router = PCCSRouter(readContractAddress(ProjectType.DCAP, "PCCSRouter"));
        AutomataDaoStorage storageContract = AutomataDaoStorage(
            readContractAddress(ProjectType.PCCS, "AutomataDaoStorage")
        );

        bool authorized = storageContract.isAuthorizedCaller(address(router));
        if (!authorized) {
            storageContract.setCallerAuthorization(address(router), true);
            console2.log("PCCSRouter granted access to AutomataDaoStorage");
        } else {
            console2.log("PCCSRouter already has access to AutomataDaoStorage");
        }

        vm.stopBroadcast();
    } 
}
