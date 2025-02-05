// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../../src/helpers/EnclaveIdentityHelper.sol";
import "../../src/helpers/FmspcTcbHelper.sol";
import "../../src/helpers/PCKHelper.sol";
import "../../src/helpers/X509CRLHelper.sol";

contract DeployHelpers is Script {
    uint256 privateKey = vm.envUint("PRIVATE_KEY");

    function deployEnclaveIdentityHelper() public {
        vm.startBroadcast(privateKey);
        EnclaveIdentityHelper enclaveIdentityHelper = new EnclaveIdentityHelper();
        console.log("[LOG] EnclaveIdentityHelper: ", address(enclaveIdentityHelper));
        vm.stopBroadcast();
    }

    function deployFmspcTcbHelper() public {
        vm.startBroadcast(privateKey);
        FmspcTcbHelper fmspcTcbHelper = new FmspcTcbHelper();
        console.log("[LOG] FmspcTcbHelper: ", address(fmspcTcbHelper));
        vm.stopBroadcast();
    }

    function deployPckHelper() public {
        vm.startBroadcast(privateKey);
        PCKHelper pckHelper = new PCKHelper();
        console.log("[LOG] PCKHelper/X509Helper: ", address(pckHelper));
        vm.stopBroadcast();
    }

    function deployX509CrlHelper() public {
        vm.startBroadcast(privateKey);
        X509CRLHelper x509Helper = new X509CRLHelper();
        console.log("[LOG] X509CRLHelper: ", address(x509Helper));
        vm.stopBroadcast();
    }
}
