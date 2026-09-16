// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "./utils/PCCSSetupBase.sol";
import {V5QuoteVerifier} from "../contracts/verifiers/V5QuoteVerifier.sol";
import {AutomataDcapAttestationFeeV2} from "../contracts/AutomataDcapAttestationFeeV2.sol";
import {OutputV2Codec} from "../contracts/utils/OutputV2Codec.sol";
import {OutputV2} from "../contracts/types/OutputV2.sol";

/// Entirely local: authentic signed Google V5 quote and frozen Intel collateral.
/// No RPC, mocked signature checks, live collateral lookup or edited quote fields.
contract QuoteV5PublicFixtureV2Test is PCCSSetupBase {
    using JSONParserLib for JSONParserLib.Item;
    using LibString for string;

    string internal fixture;
    AutomataDcapAttestationFeeV2 internal fee;
    uint32 internal evaluationNumber;

    function setUp() public override {
        fixture = vm.readFile(string.concat(vm.projectRoot(), "/forge-test/assets/v2/fixtures/v5.json"));
        vm.warp(vm.parseJsonUint(fixture, ".verificationTimestamp"));
        super.setUp();
        evaluationNumber = uint32(vm.parseJsonUint(fixture, ".tcbEvaluationDataNumber"));
        vm.startPrank(admin);
        // The base fixtures use evaluation 17; this signed snapshot uses 20.
        enclaveIdDao = new AutomataEnclaveIdentityDaoVersioned(
            address(pccsStorage),
            P256_VERIFIER,
            address(dependencyConfig),
            address(enclaveIdHelper),
            address(x509),
            admin,
            evaluationNumber
        );
        fmspcTcbDao = new AutomataFmspcTcbDaoVersioned(
            address(pccsStorage),
            P256_VERIFIER,
            address(pcsDao),
            address(tcbHelper),
            address(x509),
            address(x509Crl),
            admin,
            evaluationNumber
        );
        pccsStorage.grantDao(address(enclaveIdDao));
        pccsStorage.grantDao(address(fmspcTcbDao));
        PCCSRouter router = setupPccsRouter(admin);
        pcsDao.upsertPcsCertificates(CA.ROOT, vm.parseJsonBytes(fixture, ".rootCaCertificate"));
        pcsDao.upsertPcsCertificates(CA.PLATFORM, vm.parseJsonBytes(fixture, ".platformCaCertificate"));
        pcsDao.upsertRootCACrl(vm.parseJsonBytes(fixture, ".rootCaCrl"));
        pcsDao.upsertPcsCertificates(CA.SIGNING, vm.parseJsonBytes(fixture, ".tcbSigningCertificate"));
        pcsDao.upsertPckCrl(CA.PLATFORM, vm.parseJsonBytes(fixture, ".pckCrl"));

        string memory tcb = vm.parseJsonString(fixture, ".tcbInfoJson");
        string memory qe = vm.parseJsonString(fixture, ".qeIdentityJson");
        fmspcTcbDao.grantRoles(admin, fmspcTcbDao.ATTESTER_ROLE());
        enclaveIdDao.grantRoles(admin, enclaveIdDao.ATTESTER_ROLE());
        fmspcTcbDao.upsertFmspcTcb(TcbInfoJsonObj(_signedObject(tcb, "tcbInfo"), vm.parseJsonBytes(tcb, ".signature")));
        EnclaveIdentityJsonObj memory identity =
            EnclaveIdentityJsonObj(_signedObject(qe, "enclaveIdentity"), vm.parseJsonBytes(qe, ".signature"));
        (IdentityObj memory parsed,) = enclaveIdHelper.parseIdentityString(identity.identityStr);
        enclaveIdDao.upsertEnclaveIdentity(uint256(parsed.id), 4, identity);

        V5QuoteVerifier verifier = new V5QuoteVerifier(P256_VERIFIER, address(router));
        fee = new AutomataDcapAttestationFeeV2(admin);
        fee.setQuoteVerifier(address(verifier));
        router.setAuthorized(address(verifier), true);
        router.setAuthorized(address(fee), true);
        vm.stopPrank();
    }

    function _signedObject(string memory json, string memory key) private pure returns (string memory) {
        JSONParserLib.Item memory root = JSONParserLib.parse(json);
        JSONParserLib.Item[] memory children = root.children();
        for (uint256 i; i < children.length; ++i) {
            if (JSONParserLib.decodeString(children[i].key()).eq(key)) return children[i].value();
        }
        revert("missing signed object");
    }

    function testPublicV5MatchesFrozenNativeAndGuestJournal() public {
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        // Explicit evaluation selection avoids introducing a separate live TCB
        // evaluation-number lookup; the TCB/QE collateral itself is authenticated.
        (bool success, bytes memory journal) = fee.verifyAndAttestOnChainV2(quote, evaluationNumber, false);
        assertTrue(success, string(journal));
        assertEq(journal, vm.parseJsonBytes(fixture, ".expectedJournal"));
        OutputV2 memory output = this.decode(journal);
        assertEq(output.formatMajorVersion, 2);
        assertEq(output.formatMinorVersion, 1);
        assertEq(output.quoteVersion, 5);
        assertEq(output.quoteBodyType, 3);
        assertEq(output.quoteBody.length, 648);
        assertEq(output.fullQuoteHash, keccak256(quote));
        assertTrue(output.piidPresent);
        for (uint256 i = 600; i < 648; ++i) {
            assertEq(output.quoteBody[i], bytes1(0));
        }
    }

    function decode(bytes calldata journal) external pure returns (OutputV2 memory) {
        return OutputV2Codec.decode(journal);
    }

    function _assertRejected(bytes memory quote) private {
        _assertRejectedMode(quote, false);
        _assertRejectedMode(quote, true);
    }

    function _assertRejectedMode(bytes memory quote, bool minCheck) private {
        (bool ok, bytes memory result) = address(fee)
            .call(abi.encodeWithSignature("verifyAndAttestOnChainV2(bytes,uint32,bool)", quote, evaluationNumber, minCheck));
        if (ok) {
            (bool success,) = abi.decode(result, (bool, bytes));
            assertFalse(success, "invalid quote accepted");
        }
    }

    function testPublicV5RejectsChangedSignedBody() public {
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        quote[80] ^= 0x01;
        _assertRejected(quote);
    }

    function testPublicV5RejectsPreValidityTimestamp() public {
        vm.warp(0);
        _assertRejected(vm.parseJsonBytes(fixture, ".quote"));
    }
}
