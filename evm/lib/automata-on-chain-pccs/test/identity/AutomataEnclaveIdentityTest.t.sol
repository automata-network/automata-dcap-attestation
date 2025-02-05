// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../pcs/PCSSetupBase.t.sol";
import "./IdentityConstants.t.sol";
import {AutomataEnclaveIdentityDao} from "../../src/automata_pccs/AutomataEnclaveIdentityDao.sol";

contract AutomataEnclaveIdentityDaoTest is PCSSetupBase, IdentityConstants {
    function setUp() public override {
        super.setUp();
    }

    function testAttestEnclaveIdentity() public {
        uint256 id = 0; // QE
        uint256 version = 3;

        EnclaveIdentityJsonObj memory enclaveIdentityObj =
            EnclaveIdentityJsonObj({identityStr: string(identityStr), signature: signature});

        bytes32 attestationId = enclaveIdDao.upsertEnclaveIdentity(id, version, enclaveIdentityObj);
        assertEq(pccsStorage.collateralPointer(enclaveIdDao.ENCLAVE_ID_KEY(id, version)), attestationId);

        vm.prank(admin);
        EnclaveIdentityJsonObj memory fetched = enclaveIdDao.getEnclaveIdentity(id, version);
        assertEq(fetched.signature, enclaveIdentityObj.signature);
        assertEq(keccak256(bytes(fetched.identityStr)), keccak256(bytes(enclaveIdentityObj.identityStr)));
    }

    function testTcbIssuerChain() public readAsAuthorizedCaller {
        (bytes memory fetchedSigning, bytes memory fetchedRoot) = enclaveIdDao.getEnclaveIdentityIssuerChain();
        assertEq(keccak256(signingDer), keccak256(fetchedSigning));
        assertEq(keccak256(rootDer), keccak256(fetchedRoot));
    }
}
