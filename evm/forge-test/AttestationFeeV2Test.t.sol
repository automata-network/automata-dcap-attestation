// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import "forge-std/Test.sol";
import {AutomataDcapAttestationV2} from "../contracts/AutomataDcapAttestationV2.sol";
import {ZkCoProcessorType, ZkCoProcessorConfig} from "../contracts/AttestationEntrypointBase.sol";
import {IQuoteVerifierV2, IQuoteVerifier, Header} from "../contracts/interfaces/IQuoteVerifierV2.sol";
import {IPCCSRouter} from "../contracts/interfaces/IPCCSRouter.sol";
import {OutputV2} from "../contracts/types/OutputV2.sol";
import {OutputV2Codec} from "../contracts/utils/OutputV2Codec.sol";
import {CA} from "@automata-network/on-chain-pccs/Common.sol";
import {AutomataDcapAttestationFee} from "../contracts/AutomataDcapAttestationFee.sol";

contract FeeV2QuoteMock is IQuoteVerifierV2 {
    IPCCSRouter public immutable pccsRouter;
    uint16 public quoteVersion = 3;
    uint16 public bodyType = 1;
    bytes private body;
    uint8 private status;

    function configure(uint16 version, uint16 kind, bytes memory value, uint8 tcbStatus) external {
        quoteVersion = version;
        bodyType = kind;
        body = value;
        status = tcbStatus;
    }

    constructor(address router) {
        pccsRouter = IPCCSRouter(router);
    }

    function legacy() public view returns (bytes memory) {
        return abi.encodePacked(quoteVersion, bodyType, status, bytes6(0), body.length == 0 ? new bytes(384) : body);
    }

    function verifyQuote(Header calldata, bytes calldata, uint32) external view returns (bool, bytes memory) {
        return (true, legacy());
    }

    function verifyQuoteV2(Header calldata, bytes calldata, uint32) external view returns (bool, bytes memory) {
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
    AutomataDcapAttestationV2 fee;
    FeeV2QuoteMock quote;
    FeeV2UniversalMock universal;
    address constant ROUTER = address(0x1234);
    bytes32 constant LEGACY_ID = bytes32(uint256(1));
    bytes32 constant V2_ID = bytes32(uint256(2));
    bytes32 constant MINIMAL_ID = bytes32(uint256(3));

    function setUp() public {
        fee = new AutomataDcapAttestationV2(address(this));
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
            fee.setZkVerifierV2(ZkCoProcessorType(backend), address(universal));
            fee.addProgramIdentifierV2(ZkCoProcessorType(backend), V2_ID, false);
            fee.addProgramIdentifierV2(ZkCoProcessorType(backend), MINIMAL_ID, true);
            fee.setDefaultProgramIdentifierV2(ZkCoProcessorType(backend), V2_ID);
        }
    }

    function quoteBytes() internal pure returns (bytes memory) {
        return bytes.concat(hex"0300", new bytes(46));
    }

    function journal() internal returns (bytes memory) {
        (bool success, bytes memory output, bytes memory body) = fee.verifyAndAttestOnChainV2(quoteBytes());
        assertTrue(success);
        assertEq(body.length, 384);
        assertEq(this.decode(output).quoteBodyHash, keccak256(body));
        return output;
    }

    function decode(bytes calldata output) external pure returns (OutputV2 memory) {
        return OutputV2Codec.decode(output);
    }

    function testOnChainLegacyUnchangedAndNewEventOnly() public {
        AutomataDcapAttestationFee legacy = new AutomataDcapAttestationFee(address(this));
        legacy.setQuoteVerifier(address(quote));
        (bool success, bytes memory old) = legacy.verifyAndAttestOnChain(quoteBytes());
        assertTrue(success);
        assertEq(old, quote.legacy());
        vm.recordLogs();
        bytes memory output = journal();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics.length, 3);
        assertEq(logs[0].topics[0], keccak256("AttestationSubmittedV2(bool,uint8,uint16,uint16,bytes32,bool,bytes)"));
        assertEq(logs[0].topics[1], bytes32(uint256(2)));
        assertEq(logs[0].topics[2], bytes32(uint256(1)));
        OutputV2 memory decoded = this.decode(output);
        assertEq(decoded.fullQuoteHash, keccak256(quoteBytes()));
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

    function testProgramFamiliesDoNotCrossAndPauseRejectsV2() public {
        bytes memory output = journal();
        (bool success,) =
            fee.verifyAndAttestWithZKProofV2(output, ZkCoProcessorType.RiscZero, new bytes(4), LEGACY_ID, 0, false);
        assertFalse(success);
        fee.setZkV2Paused(true);
        (success,) = fee.verifyAndAttestWithZKProofV2(output, ZkCoProcessorType.RiscZero, new bytes(4));
        assertFalse(success);
    }

    function testLegacySelectorsAreUnavailableEvenToOwner() public {
        bytes[] memory calls = new bytes[](13);
        calls[0] = abi.encodeWithSignature("setZkConfiguration(uint8,(bytes32,address))", uint8(1), ZkCoProcessorConfig(LEGACY_ID, address(universal)));
        calls[1] = abi.encodeWithSignature("updateProgramIdentifier(uint8,bytes32)", uint8(1), LEGACY_ID);
        calls[2] = abi.encodeWithSignature("programIdentifier(uint8)", uint8(1));
        calls[3] = abi.encodeWithSignature("programIdentifiers(uint8)", uint8(1));
        calls[4] = abi.encodeWithSignature("verifyAndAttestOnChain(bytes)", quoteBytes());
        calls[5] = abi.encodeWithSignature("verifyAndAttestOnChain(bytes,uint32)", quoteBytes(), uint32(17));
        calls[6] = abi.encodeWithSignature("verifyAndAttestWithZKProof(bytes,uint8,bytes)", bytes(""), uint8(1), new bytes(4));
        calls[7] = abi.encodeWithSignature("removeProgramIdentifier(uint8,bytes32)", uint8(1), V2_ID);
        calls[8] = abi.encodeWithSignature("verifyAndAttestWithZKProof(bytes,uint8,bytes,bytes32,uint32)", bytes(""), uint8(1), new bytes(4), LEGACY_ID, uint32(17));
        calls[9] = abi.encodeWithSignature("zkVerifier(uint8)", uint8(1));
        calls[10] = abi.encodeWithSignature("zkVerifier(uint8,bytes4)", uint8(1), bytes4(0));
        calls[11] = abi.encodeWithSignature("setZkConfigurationV2(uint8,(bytes32,address))", uint8(1), ZkCoProcessorConfig(V2_ID, address(universal)));
        calls[12] = abi.encodeWithSignature("updateProgramIdentifierV2(uint8,bytes32)", uint8(1), V2_ID);
        for (uint256 i; i < calls.length; ++i) {
            (bool ok,) = address(fee).call(calls[i]);
            assertFalse(ok);
        }
        assertEq(fee.programIdentifierV2(ZkCoProcessorType.RiscZero), V2_ID);
    }

    function testRegistrationDefaultAndImmutableModeAreIndependent() public {
        ZkCoProcessorType backend = ZkCoProcessorType.RiscZero;
        bytes32 next = bytes32(uint256(99));
        fee.addProgramIdentifierV2(backend, next, false);
        assertEq(fee.programIdentifierV2(backend), V2_ID);
        fee.setDefaultProgramIdentifierV2(backend, next);
        assertEq(fee.programIdentifierV2(backend), next);
        vm.expectRevert(bytes("Default program must be strict"));
        fee.setDefaultProgramIdentifierV2(backend, MINIMAL_ID);
        vm.expectRevert(bytes("Program identifier does not exist"));
        fee.setDefaultProgramIdentifierV2(backend, bytes32(uint256(100)));
        fee.removeProgramIdentifierV2(backend, MINIMAL_ID);
        vm.expectRevert(bytes("Program mode is immutable"));
        fee.addProgramIdentifierV2(backend, MINIMAL_ID, false);
        fee.addProgramIdentifierV2(backend, MINIMAL_ID, true);
        (bool registered, bool minCheck) = fee.programModeV2(backend, MINIMAL_ID);
        assertTrue(registered && minCheck);
        vm.expectRevert();
        fee.removeProgramIdentifierV2(backend, next);
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
        fee.addProgramIdentifierV2(ZkCoProcessorType.RiscZero, bytes32(uint256(99)), false);
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
