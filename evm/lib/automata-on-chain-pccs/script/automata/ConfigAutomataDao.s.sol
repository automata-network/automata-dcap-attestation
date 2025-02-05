// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

import {AutomataDaoStorage} from "../../src/automata_pccs/shared/AutomataDaoStorage.sol";
import {AutomataFmspcTcbDao} from "../../src/automata_pccs/AutomataFmspcTcbDao.sol";
import {AutomataEnclaveIdentityDao} from "../../src/automata_pccs/AutomataEnclaveIdentityDao.sol";
import {AutomataPcsDao} from "../../src/automata_pccs/AutomataPcsDao.sol";
import {AutomataPckDao} from "../../src/automata_pccs/AutomataPckDao.sol";

contract ConfigAutomataDao is Script {
    uint256 privateKey = vm.envUint("PRIVATE_KEY");

    address pccsStorageAddr = vm.envAddress("PCCS_STORAGE");
    address pcsDaoAddr = vm.envAddress("PCS_DAO");
    address pckDaoAddr = vm.envAddress("PCK_DAO");
    address fmspcTcbDaoAddr = vm.envAddress("FMSPC_TCB_DAO");
    address enclaveIdDaoAddr = vm.envAddress("ENCLAVE_ID_DAO");

    address x509Crl = vm.envAddress("X509_CRL_HELPER");
    address x509 = vm.envAddress("X509_HELPER");
    address enclaveIdentityHelper = vm.envAddress("ENCLAVE_IDENTITY_HELPER");
    address fmspcTcbHelper = vm.envAddress("FMSPC_TCB_HELPER");

    function updateStorageDao() public {
        vm.broadcast(privateKey);

        AutomataDaoStorage pccsStorage = AutomataDaoStorage(pccsStorageAddr);
        pccsStorage.updateDao(pcsDaoAddr, pckDaoAddr, fmspcTcbDaoAddr, enclaveIdDaoAddr);
    }

    function revokeDao(address dao) public {
        vm.broadcast(privateKey);

        AutomataDaoStorage(pccsStorageAddr).revokeDao(dao);
    }

    function setAuthorizedCaller(address caller, bool authorized) public {
        vm.broadcast(privateKey);

        AutomataDaoStorage(pccsStorageAddr).setCallerAuthorization(caller, authorized);
    }
}
