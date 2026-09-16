// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "./utils/PCCSSetupBase.sol";
import {V3QuoteVerifier} from "../contracts/verifiers/V3QuoteVerifier.sol";
import {V4QuoteVerifier} from "../contracts/verifiers/V4QuoteVerifier.sol";
import {AutomataDcapAttestationFeeV2} from "../contracts/AutomataDcapAttestationFeeV2.sol";
import {OutputV2Codec} from "../contracts/utils/OutputV2Codec.sol";
import {OutputV2} from "../contracts/types/OutputV2.sol";

/// Real signatures, CRLs, DAOs and fee entrypoint; offline and no crypto mocks.
abstract contract PublicAtaQuoteV2Base is PCCSSetupBase {
    using JSONParserLib for JSONParserLib.Item;
    using LibString for string;

    string internal fixture;
    AutomataDcapAttestationFeeV2 internal fee;
    uint32 internal evaluationNumber;
    uint16 internal version;

    function fixtureName() internal pure virtual returns (string memory);

    function setUp() public override {
        fixture = vm.readFile(string.concat(vm.projectRoot(), "/forge-test/assets/v2/fixtures/", fixtureName()));
        vm.warp(vm.parseJsonUint(fixture, ".verificationTimestamp"));
        super.setUp();
        evaluationNumber = uint32(vm.parseJsonUint(fixture, ".tcbEvaluationDataNumber"));
        version = uint16(vm.parseJsonUint(fixture, ".quoteVersion"));
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
        address verifier = version == 3
            ? address(new V3QuoteVerifier(P256_VERIFIER, address(router)))
            : address(new V4QuoteVerifier(P256_VERIFIER, address(router)));
        fee = new AutomataDcapAttestationFeeV2(admin);
        fee.setQuoteVerifier(verifier);
        router.setAuthorized(verifier, true);
        router.setAuthorized(address(fee), true);
        vm.stopPrank();
    }

    function _signedObject(string memory json, string memory key) private pure returns (string memory) {
        JSONParserLib.Item[] memory children = JSONParserLib.parse(json).children();
        for (uint256 i; i < children.length; ++i) {
            if (JSONParserLib.decodeString(children[i].key()).eq(key)) return children[i].value();
        }
        revert("missing signed object");
    }

    function _quote() internal view returns (bytes memory) {
        return vm.parseJsonBytes(fixture, ".quote");
    }

    function decode(bytes calldata journal) external pure returns (OutputV2 memory) {
        return OutputV2Codec.decode(journal);
    }

    function testAuthenticQuoteMatchesFrozenJournalAndEvent() public {
        vm.recordLogs();
        (bool success, bytes memory journal) = fee.verifyAndAttestOnChainV2(_quote(), evaluationNumber, false);
        assertTrue(success, string(journal));
        assertEq(journal, vm.parseJsonBytes(fixture, ".expectedJournal"));
        OutputV2 memory output = this.decode(journal);
        assertEq(output.quoteVersion, version);
        assertEq(output.quoteBodyType, version == 3 ? 1 : 2);
        assertEq(output.timestamp, vm.parseJsonUint(fixture, ".verificationTimestamp"));
        assertEq(output.fullQuoteHash, keccak256(_quote()));
        assertTrue(output.piidPresent);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].emitter, address(fee));
        assertEq(logs[0].topics[0], keccak256("AttestationSubmittedV2(bool,uint8,uint16,uint16,bytes)"));
        assertEq(logs[0].topics[1], bytes32(uint256(2)));
        assertEq(logs[0].topics[2], bytes32(uint256(1)));
        (bool eventSuccess, uint8 backend, bytes memory eventOutput) = abi.decode(logs[0].data, (bool, uint8, bytes));
        assertTrue(eventSuccess);
        assertEq(backend, 0);
        assertEq(eventOutput, journal);
    }

    function _assertRejected(bytes memory quote) internal {
        _assertRejectedMode(quote, false);
        _assertRejectedMode(quote, true);
    }

    function _assertRejectedMode(bytes memory quote, bool minCheck) private {
        vm.recordLogs();
        (bool ok, bytes memory result) = address(fee)
            .call(abi.encodeWithSignature("verifyAndAttestOnChainV2(bytes,uint32,bool)", quote, evaluationNumber, minCheck));
        if (ok) {
            (bool success,) = abi.decode(result, (bool, bytes));
            assertFalse(success, "invalid quote accepted");
        } else {
            // Do not count an empty/OOG revert or a Solidity panic as policy rejection.
            assertGe(result.length, 4);
            assertTrue(bytes4(result) != bytes4(0x4e487b71), "unexpected Solidity panic");
        }
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].emitter == address(fee)
                    && logs[i].topics[0] == keccak256("AttestationSubmittedV2(bool,uint8,uint16,uint16,bytes)")
            ) {
                (bool success,,) = abi.decode(logs[i].data, (bool, uint8, bytes));
                assertFalse(success, "successful attestation event for invalid quote");
            }
        }
    }

    function testRejectsChangedSignedBody() public {
        bytes memory q = _quote();
        q[80] ^= 0x01;
        _assertRejected(q);
    }

    function testRejectsChangedQuoteSignature() public {
        bytes memory q = _quote();
        q[version == 3 ? 436 : 636] ^= 0x01;
        _assertRejected(q);
    }

    function testRejectsTrailingZeroPadding() public {
        _assertRejected(bytes.concat(_quote(), new bytes(3065)));
    }

    function testRejectsTruncatedQuote() public {
        bytes memory q = _quote();
        assembly { mstore(q, sub(mload(q), 1)) }
        _assertRejected(q);
    }

    function testRejectsUnsupportedQuoteVersion() public {
        bytes memory q = _quote();
        q[0] = 0x02;
        q[1] = 0x00;
        _assertRejected(q);
    }

    function testRejectsOversizedSignatureLength() public {
        bytes memory q = _quote();
        uint256 off = version == 3 ? 432 : 632;
        for (uint256 i; i < 4; ++i) {
            q[off + i] = 0xff;
        }
        _assertRejected(q);
    }

    function testRejectsPreValidityTimestamp() public {
        vm.warp(0);
        _assertRejected(_quote());
    }

    function testRejectsPostValidityTimestamp() public {
        vm.warp(block.timestamp + 400 days);
        _assertRejected(_quote());
    }
}

contract PublicAtaSgxV3Test is PublicAtaQuoteV2Base {
    function fixtureName() internal pure override returns (string memory) {
        return "ata-sgx-v3.json";
    }
}

contract PublicAtaTdxV4Test is PublicAtaQuoteV2Base {
    function fixtureName() internal pure override returns (string memory) {
        return "ata-tdx-v4.json";
    }

    function testOriginalPaddedInputRejectedButExactPrefixAuthenticated() public {
        bytes memory original =
            vm.parseBytes(vm.readFile(string.concat(vm.projectRoot(), "/forge-test/assets/v2/quotes/ata-tdx-v4.hex")));
        assertEq(original.length, 8000);
        bytes memory extracted = _quote();
        assertEq(extracted.length, 4935);
        assertEq(original, bytes.concat(extracted, new bytes(3065)));
        _assertRejected(original);
        (bool success, bytes memory journal) = fee.verifyAndAttestOnChainV2(extracted, evaluationNumber, false);
        assertTrue(success, string(journal));
        assertEq(journal, vm.parseJsonBytes(fixture, ".expectedJournal"));
    }
}
