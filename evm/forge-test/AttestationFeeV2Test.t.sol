// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "forge-std/Test.sol";
import {AutomataDcapAttestationFeeV2} from "../contracts/AutomataDcapAttestationFeeV2.sol";
import {ZkCoProcessorType, ZkCoProcessorConfig} from "../contracts/AttestationEntrypointBase.sol";
import {IQuoteVerifierV2, IQuoteVerifier, Header} from "../contracts/interfaces/IQuoteVerifierV2.sol";
import {IPCCSRouter} from "../contracts/interfaces/IPCCSRouter.sol";
import {OutputV2} from "../contracts/types/OutputV2.sol";
import {OutputV2Codec} from "../contracts/utils/OutputV2Codec.sol";
import {CA} from "@automata-network/on-chain-pccs/Common.sol";

contract FeeV2QuoteMock is IQuoteVerifierV2 {
    IPCCSRouter public immutable pccsRouter;
    uint16 public constant quoteVersion = 3;

    constructor(address router) {
        pccsRouter = IPCCSRouter(router);
    }

    function legacy() public pure returns (bytes memory) {
        return abi.encodePacked(uint16(3), uint16(1), uint8(0), bytes6(0), new bytes(384));
    }

    function verifyQuote(Header calldata, bytes calldata, uint32) external pure returns (bool, bytes memory) {
        return (true, legacy());
    }

    function verifyQuoteV2(Header calldata, bytes calldata, uint32) external pure returns (bool, bytes memory) {
        return (true, abi.encode(bytes16(uint128(1)), bytes16(0), false, legacy()));
    }

    function verifyZkOutput(bytes calldata journal, uint32) external pure returns (bool, bytes memory) {
        return (true, journal[2:2 + uint256(uint16(bytes2(journal[:2])))]);
    }
}

contract FeeV2UniversalMock {
    bytes32 expectedID;
    bytes32 expectedHash;

    function expectProof(bytes32 id, bytes memory journal) external {
        expectedID = id;
        expectedHash = sha256(journal);
    }

    function verify(bytes calldata, bytes32 id, bytes32 digest) external view {
        require(id == expectedID && digest == expectedHash, "bad proof");
    }

    function verifyProof(bytes32 id, bytes calldata journal, bytes calldata) external view {
        require(id == expectedID && sha256(journal) == expectedHash, "bad proof");
    }

    function verifyPicoProof(bytes32 id, bytes calldata journal, uint256[8] calldata) external view {
        require(id == expectedID && sha256(journal) == expectedHash, "bad proof");
    }
}

contract AttestationFeeV2Test is Test {
    AutomataDcapAttestationFeeV2 fee;
    FeeV2QuoteMock quote;
    FeeV2UniversalMock universal;
    address constant ROUTER = address(0x1234);
    bytes32 constant LEGACY_ID = bytes32(uint256(1));
    bytes32 constant V2_ID = bytes32(uint256(2));

    function setUp() public {
        fee = new AutomataDcapAttestationFeeV2(address(this));
        quote = new FeeV2QuoteMock(ROUTER);
        universal = new FeeV2UniversalMock();
        fee.setQuoteVerifier(address(quote));
        vm.mockCall(
            ROUTER,
            abi.encodeWithSelector(IPCCSRouter.getStandardTcbEvaluationDataNumberWithTimestamp.selector),
            abi.encode(uint32(17))
        );
        vm.mockCall(
            ROUTER,
            abi.encodeWithSelector(IPCCSRouter.getFmspcTcbContentHashWithTimestamp.selector),
            abi.encode(bytes32(uint256(1)))
        );
        vm.mockCall(
            ROUTER,
            abi.encodeWithSelector(IPCCSRouter.getQeIdentityContentHashWithTimestamp.selector),
            abi.encode(bytes32(uint256(2)))
        );
        vm.mockCall(
            ROUTER,
            abi.encodeWithSelector(IPCCSRouter.getCertHashWithTimestamp.selector),
            abi.encode(bytes32(uint256(3)))
        );
        vm.mockCall(
            ROUTER,
            abi.encodeWithSelector(IPCCSRouter.getCrlHashWithTimestamp.selector),
            abi.encode(bytes32(uint256(4)))
        );
        for (uint8 backend = 1; backend <= 3; ++backend) {
            fee.setZkConfiguration(ZkCoProcessorType(backend), ZkCoProcessorConfig(LEGACY_ID, address(universal)));
            fee.setZkConfigurationV2(ZkCoProcessorType(backend), ZkCoProcessorConfig(V2_ID, address(universal)));
        }
    }

    function quoteBytes() internal pure returns (bytes memory) {
        return bytes.concat(hex"0300", new bytes(46));
    }

    function journal() internal returns (bytes memory) {
        (bool success, bytes memory output) = fee.verifyAndAttestOnChainV2(quoteBytes());
        assertTrue(success);
        return output;
    }

    function decode(bytes calldata output) external pure returns (OutputV2 memory) {
        return OutputV2Codec.decode(output);
    }

    function testOnChainLegacyUnchangedAndNewEventOnly() public {
        (bool success, bytes memory old) = fee.verifyAndAttestOnChain(quoteBytes());
        assertTrue(success);
        assertEq(old, quote.legacy());
        vm.recordLogs();
        bytes memory output = journal();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics.length, 3);
        assertEq(logs[0].topics[0], keccak256("AttestationSubmittedV2(bool,uint8,uint16,uint16,bytes)"));
        assertEq(logs[0].topics[1], bytes32(uint256(2)));
        assertEq(logs[0].topics[2], bytes32(uint256(1)));
        OutputV2 memory decoded = this.decode(output);
        assertEq(decoded.fullQuoteHash, sha256(quoteBytes()));
        assertEq(decoded.timestamp, block.timestamp);
        assertEq(decoded.ppid, bytes16(uint128(1)));
    }

    function testAllBackendsReturnJournalVerbatim() public {
        bytes memory output = journal();
        universal.expectProof(V2_ID, output);
        for (uint8 backend = 1; backend <= 3; ++backend) {
            bytes memory proof = backend == 3 ? new bytes(260) : new bytes(4);
            (bool success, bytes memory verified) =
                fee.verifyAndAttestWithZKProofV2(output, ZkCoProcessorType(backend), proof);
            assertTrue(success);
            assertEq(verified, output);
        }
    }

    function testProgramFamiliesDoNotCrossAndRollbackPreservesLegacy() public {
        bytes memory output = journal();
        (bool success,) =
            fee.verifyAndAttestWithZKProofV2(output, ZkCoProcessorType.RiscZero, new bytes(4), LEGACY_ID, 0);
        assertFalse(success);
        (success,) = fee.verifyAndAttestWithZKProof(output, ZkCoProcessorType.RiscZero, new bytes(4), V2_ID, 0);
        assertFalse(success);
        fee.setZkV2Paused(true);
        (success,) = fee.verifyAndAttestWithZKProofV2(output, ZkCoProcessorType.RiscZero, new bytes(4));
        assertFalse(success);
        bytes memory old = quote.legacy();
        bytes memory legacyJournal = abi.encodePacked(uint16(old.length), old, new bytes(200));
        universal.expectProof(LEGACY_ID, legacyJournal);
        bytes memory verified;
        (success, verified) = fee.verifyAndAttestWithZKProof(legacyJournal, ZkCoProcessorType.RiscZero, new bytes(4));
        assertTrue(success);
        assertEq(verified, old);
        assertEq(fee.programIdentifier(ZkCoProcessorType.RiscZero), LEGACY_ID);
    }

    function testInvalidProofAndCollateralRejected() public {
        bytes memory output = journal();
        vm.expectRevert(bytes("bad proof"));
        fee.verifyAndAttestWithZKProofV2(output, ZkCoProcessorType.RiscZero, new bytes(4));
        output[65] = 0xff;
        universal.expectProof(V2_ID, output);
        (bool success,) = fee.verifyAndAttestWithZKProofV2(output, ZkCoProcessorType.RiscZero, new bytes(4));
        assertFalse(success);
    }

    function testAdminOnlyV2Configuration() public {
        vm.prank(address(42));
        vm.expectRevert();
        fee.setZkV2Paused(true);
        vm.prank(address(42));
        vm.expectRevert();
        fee.updateProgramIdentifierV2(ZkCoProcessorType.RiscZero, bytes32(uint256(99)));
    }

    function testV2ProofFramingFailuresAndStrictJournalReverts() public {
        bytes memory output = journal();
        for (uint8 backend = 1; backend <= 3; ++backend) {
            for (uint256 size; size < 4; ++size) {
                (bool success, bytes memory reason) = fee.verifyAndAttestWithZKProofV2(
                    output, ZkCoProcessorType(backend), new bytes(size)
                );
                assertFalse(success);
                assertEq(string(reason), "Invalid ZK proof length");
            }
            // Canonical wire decoding intentionally uses a typed revert, not a slicing panic.
            vm.expectRevert(OutputV2Codec.InvalidOutputV2.selector);
            fee.verifyAndAttestWithZKProofV2(hex"0201", ZkCoProcessorType(backend), new bytes(4));
        }
        (bool ok, bytes memory error) = fee.verifyAndAttestWithZKProofV2(
            output, ZkCoProcessorType.Pico, new bytes(259)
        );
        assertFalse(ok);
        assertEq(string(error), "Invalid Pico proof length");
    }
}
