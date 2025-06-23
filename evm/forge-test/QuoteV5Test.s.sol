// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./utils/PCCSSetupBase.sol";

import {
    AutomataDcapAttestationFee,
    ZkCoProcessorConfig,
    ZkCoProcessorType
} from "../contracts/AutomataDcapAttestationFee.sol";

import {V5QuoteVerifier} from "../contracts/verifiers/V5QuoteVerifier.sol";

contract QuoteV5Test is PCCSSetupBase {
    AutomataDcapAttestationFee attestation;
    PCCSRouter pccsRouter;

    function setUp() public override {
        // comment this line out if you are replacing sampleQuote with your own
        // this line is needed to bypass expiry reverts for stale quotes
        vm.warp(1749945600); // pinned June 15th, 2025, 12am UTC

        super.setUp();
        vm.startPrank(admin);

        // PCCS Setup
        pccsRouter = setupPccsRouter(admin);
        pcsDaoUpserts();

        // DCAP Contract Deployment
        attestation = new AutomataDcapAttestationFee(admin);

        vm.stopPrank();
    }

    function testQuoteV5TD15() public {
        V5QuoteVerifier quoteVerifier = new V5QuoteVerifier(P256_VERIFIER, address(pccsRouter));

        bytes memory sampleQuote = vm.readFileBinary(
            string.concat(
                vm.projectRoot(),
                "/forge-test/assets/quotes/alibaba_quote_5.dat"
            )
        );

        vm.startPrank(admin);

        attestation.setQuoteVerifier(address(quoteVerifier));
        pccsRouter.setAuthorized(address(quoteVerifier), true);
        assertEq(address(attestation.quoteVerifiers(5)), address(quoteVerifier));

        // collateral upserts
        string memory tcbInfoPath = "/forge-test/assets/0625/tcbinfov3_90c06f000000.json";
        string memory qeIdPath = "/forge-test/assets/0625/qe_td.json";

        enclaveIdDao.grantRoles(
            admin,
            enclaveIdDao.ATTESTER_ROLE()
        );
        qeIdDaoUpsert(4, qeIdPath);
        fmspcTcbDao.grantRoles(
            admin,
            fmspcTcbDao.ATTESTER_ROLE()
        );
        fmspcTcbDaoUpsert(tcbInfoPath);

        string memory tdxEvalPath = "/forge-test/assets/0625/tdxtcbeval.json";
        tcbEvalDaoUpsert(tdxEvalPath);

        vm.stopPrank();

        (bool success, bytes memory output) = attestation.verifyAndAttestOnChain(sampleQuote);
        if (!success) {
            console.log(string(output));
        }
        assertTrue(success);
    }
}