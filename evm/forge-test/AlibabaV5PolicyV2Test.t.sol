// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "./utils/PCCSSetupBase.sol";
import {V5QuoteVerifier} from "../contracts/verifiers/V5QuoteVerifier.sol";
import {AutomataDcapAttestationV2} from "../contracts/AutomataDcapAttestationV2.sol";
import {OutputV2Codec} from "../contracts/utils/OutputV2Codec.sol";
import {OutputV2} from "../contracts/types/OutputV2.sol";

/// Entirely local: authentic signed Alibaba V5 quote with non-zero MR_SERVICE_TD
/// and frozen Intel collateral (donated by the Google V5 fixture, same FMSPC).
/// Strict mode must reject with the migration-service policy error; minimal
/// mode must accept and reproduce the frozen compact journal. No RPC, mocked
/// signature checks, live collateral lookup or edited quote fields.
contract AlibabaV5PolicyV2Test is PCCSSetupBase {
    using JSONParserLib for JSONParserLib.Item;
    using LibString for string;

    string internal fixture;
    AutomataDcapAttestationV2 internal fee;
    uint32 internal evaluationNumber;

    function setUp() public override {
        fixture = vm.readFile(string.concat(vm.projectRoot(), "/forge-test/assets/v2/fixtures/alibaba-v5.json"));
        vm.warp(vm.parseJsonUint(fixture, ".verificationTimestamp"));
        super.setUp();
        evaluationNumber = uint32(vm.parseJsonUint(fixture, ".tcbEvaluationDataNumber"));
        vm.startPrank(admin);
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
        fee = new AutomataDcapAttestationV2(admin);
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

    function decode(bytes calldata journal) external pure returns (OutputV2 memory) {
        return OutputV2Codec.decode(journal);
    }

    function testAlibabaV5StrictRejectsMigrationServiceTd() public {
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        vm.expectRevert(bytes("TDX migration service TD measurement is not zero"));
        fee.verifyAndAttestOnChainV2(quote, evaluationNumber, false);
    }

    function testAlibabaV5MinimalAcceptsAndMatchesFrozenJournal() public {
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        (bool success, bytes memory journal, bytes memory body) = fee.verifyAndAttestOnChainV2(quote, evaluationNumber, true);
        assertTrue(success, string(journal));
        assertEq(journal, vm.parseJsonBytes(fixture, ".expectedJournal"));
        OutputV2 memory output = this.decode(journal);
        assertEq(output.formatMajorVersion, 2);
        assertEq(output.formatMinorVersion, 1);
        assertEq(output.quoteVersion, 5);
        assertEq(output.quoteBodyType, 3);
        assertEq(body.length, 648);
        assertEq(output.quoteBodyHash, keccak256(body));
        assertEq(output.fullQuoteHash, keccak256(quote));
        assertTrue(output.piidPresent);
        // The authenticated body carries the non-zero migration service TD.
        bool nonzero;
        for (uint256 i = 600; i < 648; ++i) {
            if (body[i] != bytes1(0)) nonzero = true;
        }
        assertTrue(nonzero, "fixture no longer carries a migration service TD");
    }

    function testAlibabaV5RejectsChangedSignedBodyInBothModes() public {
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        quote[80] ^= 0x01;
        for (uint256 mode; mode < 2; ++mode) {
            (bool ok, bytes memory result) = address(fee)
                .call(abi.encodeWithSignature("verifyAndAttestOnChainV2(bytes,uint32,bool)", quote, evaluationNumber, mode == 1));
            if (ok) {
                (bool accepted,,) = abi.decode(result, (bool, bytes, bytes));
                assertFalse(accepted, "modified quote accepted");
            }
        }
    }

    function testAlibabaV5RejectsPreValidityTimestampInBothModes() public {
        vm.warp(0);
        bytes memory quote = vm.parseJsonBytes(fixture, ".quote");
        for (uint256 mode; mode < 2; ++mode) {
            (bool ok, bytes memory result) = address(fee)
                .call(abi.encodeWithSignature("verifyAndAttestOnChainV2(bytes,uint32,bool)", quote, evaluationNumber, mode == 1));
            if (ok) {
                (bool accepted,,) = abi.decode(result, (bool, bytes, bytes));
                assertFalse(accepted, "expired collateral accepted");
            }
        }
    }
}
