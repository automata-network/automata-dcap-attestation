// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../utils/P256Configuration.sol";

import {AutomataDaoStorage} from "../../src/automata_pccs/shared/AutomataDaoStorage.sol";
import {AutomataFmspcTcbDao} from "../../src/automata_pccs/AutomataFmspcTcbDao.sol";
import {AutomataEnclaveIdentityDao} from "../../src/automata_pccs/AutomataEnclaveIdentityDao.sol";
import {AutomataPcsDao} from "../../src/automata_pccs/AutomataPcsDao.sol";
import {AutomataPckDao} from "../../src/automata_pccs/AutomataPckDao.sol";

contract DeployAutomataDao is P256Configuration {
    uint256 privateKey = vm.envUint("PRIVATE_KEY");

    address x509Crl = vm.envAddress("X509_CRL_HELPER");
    address x509 = vm.envAddress("X509_HELPER");
    address enclaveIdentityHelper = vm.envAddress("ENCLAVE_IDENTITY_HELPER");
    address fmspcTcbHelper = vm.envAddress("FMSPC_TCB_HELPER");

    modifier broadcastKey(uint256 key) {
        vm.startBroadcast(key);
        _;
        vm.stopBroadcast();
    }

    function deployAll(bool shouldDeployStorage) public broadcastKey(privateKey) {
        AutomataDaoStorage pccsStorage;
        if (shouldDeployStorage) {
            pccsStorage = new AutomataDaoStorage();
            console.log("AutomataDaoStorage deployed at ", address(pccsStorage));
        } else {
            address pccsStorageAddr = vm.envAddress("PCCS_STORAGE");
            pccsStorage = AutomataDaoStorage(pccsStorageAddr);
        }

        // Deploy PcsDao
        AutomataPcsDao pcsDao = new AutomataPcsDao(address(pccsStorage), simulateVerify(), x509, x509Crl);
        console.log("AutomataPcsDao deployed at: ", address(pcsDao));

        // Deploy PckDao
        AutomataPckDao pckDao =
            new AutomataPckDao(address(pccsStorage), simulateVerify(), address(pcsDao), x509, x509Crl);
        console.log("AutomataPckDao deployed at: ", address(pckDao));

        // Deploy EnclaveIdDao
        AutomataEnclaveIdentityDao enclaveIdDao = new AutomataEnclaveIdentityDao(
            address(pccsStorage), simulateVerify(), address(pcsDao), enclaveIdentityHelper, x509
        );
        console.log("AutomataEnclaveIdDao deployed at: ", address(enclaveIdDao));

        // Deploy FmspcDao
        AutomataFmspcTcbDao fmspcTcbDao =
            new AutomataFmspcTcbDao(address(pccsStorage), simulateVerify(), address(pcsDao), fmspcTcbHelper, x509);
        console.log("AutomataFmspcTcbDao deployed at: ", address(fmspcTcbDao));

        pccsStorage.updateDao(address(pcsDao), address(pckDao), address(fmspcTcbDao), address(enclaveIdDao));
    }

    function deployStorage() public broadcastKey(privateKey) {
        AutomataDaoStorage pccsStorage = new AutomataDaoStorage();

        console.log("AutomataDaoStorage deployed at ", address(pccsStorage));
    }

    function deployPcs() public broadcastKey(privateKey) {
        address pccsStorageAddr = vm.envAddress("PCCS_STORAGE");

        AutomataPcsDao pcsDao = new AutomataPcsDao(pccsStorageAddr, simulateVerify(), x509, x509Crl);

        console.log("AutomataPcsDao deployed at: ", address(pcsDao));
    }

    function deployPck() public broadcastKey(privateKey) {
        address pccsStorageAddr = vm.envAddress("PCCS_STORAGE");
        address pcsDaoAddr = vm.envAddress("PCS_DAO");

        AutomataPckDao pckDao = new AutomataPckDao(pccsStorageAddr, simulateVerify(), pcsDaoAddr, x509, x509Crl);


        console.log("AutomataPckDao deployed at: ", address(pckDao));
    }

    function deployEnclaveIdDao() public broadcastKey(privateKey) {
        address pccsStorageAddr = vm.envAddress("PCCS_STORAGE");
        address pcsDaoAddr = vm.envAddress("PCS_DAO");

        AutomataEnclaveIdentityDao enclaveIdDao =
            new AutomataEnclaveIdentityDao(pccsStorageAddr, simulateVerify(), pcsDaoAddr, enclaveIdentityHelper, x509);

        console.log("AutomataEnclaveIdDao deployed at: ", address(enclaveIdDao));
    }

    function deployFmspcTcbDao() public broadcastKey(privateKey) {
        address pccsStorageAddr = vm.envAddress("PCCS_STORAGE");
        address pcsDaoAddr = vm.envAddress("PCS_DAO");

        AutomataFmspcTcbDao fmspcTcbDao =
            new AutomataFmspcTcbDao(pccsStorageAddr, simulateVerify(), pcsDaoAddr, fmspcTcbHelper, x509);

        console.log("AutomataFmspcTcbDao deployed at: ", address(fmspcTcbDao));
    }
}
