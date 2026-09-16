// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {AutomataDcapAttestationFee} from "./AutomataDcapAttestationFee.sol";
import "./AttestationEntrypointBase.sol";
import {IQuoteVerifierV2} from "./interfaces/IQuoteVerifierV2.sol";
import {OutputV2Codec} from "./utils/OutputV2Codec.sol";
import {OutputV2} from "./types/OutputV2.sol";
import {IPCCSRouter} from "./interfaces/IPCCSRouter.sol";
import {TcbId} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";
import {EnclaveId} from "@automata-network/on-chain-pccs/helpers/EnclaveIdentityHelper.sol";
import {CA} from "@automata-network/on-chain-pccs/bases/PcsDao.sol";
import {BytesUtils} from "./utils/BytesUtils.sol";
import {QuotePolicyV2} from "./utils/QuotePolicyV2.sol";

/// @notice New deployment retaining every legacy selector and its original validation/output semantics.
contract AutomataDcapAttestationFeeV2 is AutomataDcapAttestationFee {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using BytesUtils for bytes;

    mapping(ZkCoProcessorType => ZkCoProcessorConfig) internal _zkConfigV2;
    mapping(ZkCoProcessorType => EnumerableSet.Bytes32Set) internal _programIdConfigV2;
    bool public zkV2Paused;

    event AttestationSubmittedV2(
        bool success,
        ZkCoProcessorType verifierType,
        uint16 indexed formatMajorVersion,
        uint16 indexed formatMinorVersion,
        bytes output
    );
    event ZkCoProcessorUpdatedV2(
        ZkCoProcessorType indexed zkCoProcessor, bytes32 programIdentifier, address zkVerifier
    );
    event ZkProgramIdentifierRemovedV2(ZkCoProcessorType indexed zkCoProcessor, bytes32 programIdentifier);
    event ZkV2PauseUpdated(bool paused);

    constructor(address owner) AutomataDcapAttestationFee(owner) {}

    function setZkConfigurationV2(ZkCoProcessorType backend, ZkCoProcessorConfig calldata config)
        external
        onlyOwner
        noneZkConfigCheck(backend)
    {
        require(config.latestDcapProgramIdentifier != bytes32(0), "Program identifier cannot be zero");
        require(config.defaultZkVerifier.code.length != 0, "ZK Verifier has no code");
        _zkConfigV2[backend] = config;
        _programIdConfigV2[backend].add(config.latestDcapProgramIdentifier);
        emit ZkCoProcessorUpdatedV2(backend, config.latestDcapProgramIdentifier, config.defaultZkVerifier);
    }

    function updateProgramIdentifierV2(ZkCoProcessorType backend, bytes32 identifier)
        external
        onlyOwner
        noneZkConfigCheck(backend)
    {
        require(identifier != bytes32(0), "Program identifier cannot be zero");
        require(
            _zkConfigV2[backend].latestDcapProgramIdentifier != identifier, "Program identifier is already the latest"
        );
        _zkConfigV2[backend].latestDcapProgramIdentifier = identifier;
        _programIdConfigV2[backend].add(identifier);
        emit ZkCoProcessorUpdatedV2(backend, identifier, _zkConfigV2[backend].defaultZkVerifier);
    }

    function removeProgramIdentifierV2(ZkCoProcessorType backend, bytes32 identifier)
        external
        onlyOwner
        noneZkConfigCheck(backend)
    {
        require(_programIdConfigV2[backend].contains(identifier), "Program identifier does not exist");
        if (_zkConfigV2[backend].latestDcapProgramIdentifier == identifier) {
            revert Cannot_Remove_ProgramIdentifier(backend, identifier);
        }
        _programIdConfigV2[backend].remove(identifier);
        emit ZkProgramIdentifierRemovedV2(backend, identifier);
    }

    /// @notice Allows rollback of all V2 proofs without freezing legacy proof routes or removing legacy IDs.
    function setZkV2Paused(bool paused) external onlyOwner {
        zkV2Paused = paused;
        emit ZkV2PauseUpdated(paused);
    }

    function programIdentifierV2(ZkCoProcessorType backend) public view returns (bytes32) {
        return _zkConfigV2[backend].latestDcapProgramIdentifier;
    }

    function programIdentifiersV2(ZkCoProcessorType backend) external view returns (bytes32[] memory) {
        return _programIdConfigV2[backend].values();
    }

    /// @dev Universal proof-selector routes (including security freezes) are shared with legacy verification.
    function zkVerifierV2(ZkCoProcessorType backend, bytes4 selector) public view returns (address) {
        address verifier = _zkVerifierConfig[backend][selector];
        if (verifier == FROZEN) revert ZK_Route_Frozen(backend, selector);
        return verifier == address(0) ? _zkConfigV2[backend].defaultZkVerifier : verifier;
    }

    function verifyAndAttestOnChainV2(bytes calldata rawQuote)
        external
        payable
        collectFee
        returns (bool, bytes memory)
    {
        return _onChainV2(rawQuote, 0, false);
    }

    /// @notice minCheck skips workload attribute policy only, never authentication or strict parsing.
    function verifyAndAttestOnChainV2(bytes calldata rawQuote, uint32 tcbEvaluationDataNumber, bool minCheck)
        external
        payable
        collectFee
        returns (bool, bytes memory)
    {
        return _onChainV2(rawQuote, tcbEvaluationDataNumber, minCheck);
    }

    function verifyAndAttestWithZKProofV2(bytes calldata journal, ZkCoProcessorType backend, bytes calldata proof)
        external
        payable
        collectFee
        returns (bool, bytes memory)
    {
        return _withProofV2(journal, backend, proof, programIdentifierV2(backend), 0, false);
    }

    /// @notice minCheck skips workload attributes only; the proof must authenticate the full V2 journal.
    function verifyAndAttestWithZKProofV2(
        bytes calldata journal,
        ZkCoProcessorType backend,
        bytes calldata proof,
        bytes32 identifier,
        uint32 tcbEvaluationDataNumber,
        bool minCheck
    ) external payable collectFee returns (bool, bytes memory) {
        return _withProofV2(journal, backend, proof, identifier, tcbEvaluationDataNumber, minCheck);
    }

    function _onChainV2(bytes calldata rawQuote, uint32 tcbEval, bool minCheck)
        private
        returns (bool success, bytes memory output)
    {
        Header memory header;
        (success, header) = _parseQuoteHeader(rawQuote);
        if (!success) return (false, bytes("Quote length is less than Header length"));
        IQuoteVerifierV2 verifier = IQuoteVerifierV2(address(quoteVerifiers[header.version]));
        if (address(verifier) == address(0)) return (false, bytes("Unsupported quote version"));
        (success, output) = verifier.verifyQuoteV2(header, rawQuote, tcbEval);
        if (success) output = _formatOutputV2(output, rawQuote, verifier.pccsRouter(), tcbEval, minCheck);
        emit AttestationSubmittedV2(success, ZkCoProcessorType.None, 2, 1, output);
    }

    function _withProofV2(
        bytes calldata journal,
        ZkCoProcessorType backend,
        bytes calldata proof,
        bytes32 identifier,
        uint32 tcbEval,
        bool minCheck
    ) private returns (bool success, bytes memory output) {
        if (zkV2Paused) return (false, bytes("V2 ZK verification is paused"));
        if (backend == ZkCoProcessorType.None || !_programIdConfigV2[backend].contains(identifier)) {
            return (false, bytes("Invalid V2 ZK Program Identifier"));
        }
        if (proof.length < 4) return (false, bytes("Invalid ZK proof length"));
        address verifier = zkVerifierV2(backend, bytes4(proof[:4]));
        if (verifier.code.length == 0) return (false, bytes("ZK Verifier is not configured"));
        OutputV2 memory decoded = OutputV2Codec.decode(journal);
        if (!minCheck) QuotePolicyV2.validate(decoded.quoteBodyType, decoded.quoteBody);
        if (backend == ZkCoProcessorType.RiscZero) {
            IRiscZeroVerifier(verifier).verify(proof, identifier, sha256(journal));
        } else if (backend == ZkCoProcessorType.Succinct) {
            ISP1Verifier(verifier).verifyProof(identifier, journal, proof);
        } else {
            if (proof.length != 260) return (false, bytes("Invalid Pico proof length"));
            IPicoVerifier(verifier).verifyPicoProof(identifier, journal, abi.decode(proof[4:], (uint256[8])));
        }
        IQuoteVerifierV2 quoteVerifier = IQuoteVerifierV2(address(quoteVerifiers[decoded.quoteVersion]));
        if (address(quoteVerifier) == address(0)) return (false, bytes("Unsupported quote version"));
        if (decoded.tcbStatus == 6 || decoded.tcbStatus == 7) return (false, bytes("Invalid V2 TCB status"));
        bytes32[6] memory expected = _collateralHashesV2(quoteVerifier.pccsRouter(), decoded, tcbEval);
        if (keccak256(abi.encode(expected)) != keccak256(abi.encode(decoded.collateralHashes))) {
            return (false, bytes("V2 collateral hash mismatch"));
        }
        success = true;
        output = journal;
        emit AttestationSubmittedV2(success, backend, 2, 1, output);
    }

    function _formatOutputV2(
        bytes memory envelope,
        bytes calldata rawQuote,
        IPCCSRouter router,
        uint32 tcbEval,
        bool minCheck
    ) private view returns (bytes memory) {
        OutputV2 memory out;
        bytes memory legacy;
        (out.ppid, out.piid, out.piidPresent, legacy) = abi.decode(envelope, (bytes16, bytes16, bool, bytes));
        out.formatMajorVersion = 2;
        out.formatMinorVersion = 1;
        out.quoteVersion = uint16(bytes2(legacy.substring(0, 2)));
        out.quoteBodyType = uint16(bytes2(legacy.substring(2, 2)));
        out.tcbStatus = uint8(legacy[4]);
        require(out.tcbStatus != 6 && out.tcbStatus != 7, "Invalid V2 TCB status");
        out.fmspc = bytes6(legacy.substring(5, 6));
        out.timestamp = uint64(block.timestamp);
        out.fullQuoteHash = keccak256(rawQuote);
        uint256 length = OutputV2Codec.bodyLength(out.quoteVersion, out.quoteBodyType);
        out.quoteBody = legacy.substring(11, length);
        if (!minCheck) QuotePolicyV2.validate(out.quoteBodyType, out.quoteBody);
        out.advisoryIDs = legacy.length == 11 + length
            ? new string[](0)
            : abi.decode(legacy.substring(11 + length, legacy.length - 11 - length), (string[]));
        out.collateralHashes = _collateralHashesV2(router, out, tcbEval);
        return OutputV2Codec.encode(out);
    }

    function _collateralHashesV2(IPCCSRouter router, OutputV2 memory out, uint32 tcbEval)
        private
        view
        returns (bytes32[6] memory hashes)
    {
        TcbId tcbId = out.quoteBodyType == 1 ? TcbId.SGX : TcbId.TDX;
        if (tcbEval == 0) tcbEval = router.getStandardTcbEvaluationDataNumberWithTimestamp(tcbId, out.timestamp);
        hashes[0] = router.getFmspcTcbContentHashWithTimestamp(tcbId, out.fmspc, 3, tcbEval, out.timestamp);
        hashes[1] = router.getQeIdentityContentHashWithTimestamp(
            out.quoteBodyType == 1 ? EnclaveId.QE : EnclaveId.TD_QE, 4, tcbEval, out.timestamp
        );
        hashes[2] = router.getCertHashWithTimestamp(CA.ROOT, out.timestamp);
        hashes[3] = router.getCertHashWithTimestamp(CA.SIGNING, out.timestamp);
        hashes[4] = router.getCrlHashWithTimestamp(CA.ROOT, out.timestamp);
        hashes[5] = router.getCrlHashWithTimestamp(out.piidPresent ? CA.PLATFORM : CA.PROCESSOR, out.timestamp);
    }
}
