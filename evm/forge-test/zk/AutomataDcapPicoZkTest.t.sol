// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../utils/PCCSSetupBase.sol";
import {PicoVerifier} from "../../contracts/zk/pico/PicoVerifier.sol";

import "../../contracts/PCCSRouter.sol";
import "../../contracts/AutomataDcapAttestationFee.sol";
import "../../contracts/verifiers/V4QuoteVerifier.sol";

contract AutomataDcapPicoZkTest is PCCSSetupBase {
    AutomataDcapAttestationFee attestation;
    V4QuoteVerifier quoteVerifier;
    PCCSRouter pccsRouter;
    
    PCCSRouter router;
    PicoVerifier picoVerifier;
    bytes32 picoDcapRiscvVkey = 0x005d101ee70878fa39780af6665162cfd3ebe8e9c2b28eb9e9aa65b3890ac876;
    bytes4 constant PICO_VERIFICATION_SELECTOR = bytes4(0); // TEMP for backward compatibility

    function setUp() public override {
        vm.warp(1761289818); // pinned at October 24, 2025, 0710h UTC
        
        super.setUp();
        
        vm.startPrank(admin);

        picoVerifier = new PicoVerifier();

        pccsRouter = setupPccsRouter(admin);
        pcsDaoUpserts();
        
        bytes memory platformCrlDer = vm.readFileBinary(
            string.concat(
                vm.projectRoot(),
                "/forge-test/assets/1025/pck_crl.der"
            )
        );
        pcsDao.upsertPckCrl(
            CA.PLATFORM, 
            platformCrlDer
        );

        enclaveIdDao.grantRoles(
            admin,
            enclaveIdDao.ATTESTER_ROLE()
        );
        qeIdDaoUpsert(4, "/forge-test/assets/1025/identity.json");

        fmspcTcbDao.grantRoles(
            admin,
            fmspcTcbDao.ATTESTER_ROLE()
        );
        fmspcTcbDaoUpsert("/forge-test/assets/1025/tcb_info.json");

        tcbEvalDaoUpsert("/forge-test/assets/1025/tdxtcbeval.json");

        attestation = new AutomataDcapAttestationFee(admin);
        quoteVerifier = new V4QuoteVerifier(P256_VERIFIER, address(pccsRouter));
        attestation.setQuoteVerifier(address(quoteVerifier));
        
        vm.stopPrank();
    }

    function testPicoGroth16Verification() public {
        vm.startPrank(admin);
        attestation.setZkConfiguration(
            ZkCoProcessorType.Pico,
            ZkCoProcessorConfig({latestDcapProgramIdentifier: picoDcapRiscvVkey, defaultZkVerifier: address(picoVerifier)})
        );
        // TEMP
        attestation.addVerifyRoute(
            ZkCoProcessorType.Pico,
            PICO_VERIFICATION_SELECTOR,
            address(picoVerifier)
        );
        vm.stopPrank();

        string memory picoInputPath = string.concat(
            vm.projectRoot(),
            "/forge-test/assets/1025/pico/inputs.json"
        );
        string memory picoInputJson = vm.readFile(picoInputPath);
        bytes memory publicValues = abi.decode(
            vm.parseJson(picoInputJson, ".publicValues"),
            (bytes)
        );
        bytes32[] memory proofBytes32 = abi.decode(
            vm.parseJson(picoInputJson, ".proof"),
            (bytes32[])
        );

        uint256[8] memory proofArray;
        for (uint256 i = 0; i < 8; i++) {
            proofArray[i] = uint256(proofBytes32[i]);
        }

        bytes memory proof = abi.encodePacked(
            PICO_VERIFICATION_SELECTOR,
            abi.encode(proofArray)
        );

        (bool success, bytes memory data) =
            attestation.verifyAndAttestWithZKProof(publicValues, ZkCoProcessorType.Pico, proof);

        assertTrue(success, string(data));
    }
}