//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {TCBStatus} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";

import {IQuoteVerifier, IPCCSRouter} from "../interfaces/IQuoteVerifier.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";
import {BELE} from "../utils/BELE.sol";
import {P256Verifier} from "../utils/P256Verifier.sol";

import {Header, EnclaveReport, Output} from "../types/CommonStruct.sol";
import "../types/Constants.sol";

import "./EnclaveIdBase.sol";
import "./X509ChainBase.sol";

abstract contract QuoteVerifierBase is IQuoteVerifier, EnclaveIdBase, X509ChainBase {
    using BytesUtils for bytes;

    IPCCSRouter public immutable override pccsRouter;
    uint16 public immutable override quoteVersion;

    constructor(address _router, uint16 _version) {
        pccsRouter = IPCCSRouter(_router);
        quoteVersion = _version;
    }

    function validateHeader(Header calldata header, uint256 quoteLength, bool teeIsValid)
        internal
        view
        returns (bool valid, string memory reason)
    {
        if (quoteLength < MINIMUM_QUOTE_LENGTH) {
            return (false, "Quote length is less than minimum");
        }

        if (header.version != quoteVersion) {
            return (false, "Version mismatch");
        }

        if (header.attestationKeyType != SUPPORTED_ATTESTATION_KEY_TYPE) {
            return (false, "Unsupported attestation key type");
        }

        if (!teeIsValid) {
            return (false, "Unknown TEE type");
        }

        if (header.qeVendorId != VALID_QE_VENDOR_ID) {
            return (false, "Not a valid Intel SGX QE Vendor ID");
        }

        valid = true;
    }

    function parseEnclaveReport(bytes memory rawEnclaveReport)
        internal
        pure
        returns (bool success, EnclaveReport memory enclaveReport)
    {
        if (rawEnclaveReport.length != ENCLAVE_REPORT_LENGTH) {
            return (false, enclaveReport);
        }
        enclaveReport.cpuSvn = bytes16(rawEnclaveReport.substring(0, 16));
        enclaveReport.miscSelect = bytes4(rawEnclaveReport.substring(16, 4));
        enclaveReport.reserved1 = bytes28(rawEnclaveReport.substring(20, 28));
        enclaveReport.attributes = bytes16(rawEnclaveReport.substring(48, 16));
        enclaveReport.mrEnclave = bytes32(rawEnclaveReport.substring(64, 32));
        enclaveReport.reserved2 = bytes32(rawEnclaveReport.substring(96, 32));
        enclaveReport.mrSigner = bytes32(rawEnclaveReport.substring(128, 32));
        enclaveReport.reserved3 = rawEnclaveReport.substring(160, 96);
        enclaveReport.isvProdId = uint16(BELE.leBytesToBeUint(rawEnclaveReport.substring(256, 2)));
        enclaveReport.isvSvn = uint16(BELE.leBytesToBeUint(rawEnclaveReport.substring(258, 2)));
        enclaveReport.reserved4 = rawEnclaveReport.substring(260, 60);
        enclaveReport.reportData = rawEnclaveReport.substring(320, 64);
        success = true;
    }

    function fetchQeIdentityAndCheckQeReport(EnclaveId id, EnclaveReport memory qeReport)
        internal
        view
        returns (bool success, EnclaveIdTcbStatus qeTcbStatus)
    {
        IdentityObj memory qeIdentity;
        (success, qeIdentity) = pccsRouter.getQeIdentity(id, quoteVersion);
        if (!success) {
            return (success, EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED);
        }
        (success, qeTcbStatus) = verifyQEReportWithIdentity(
            qeIdentity, qeReport.miscSelect, qeReport.attributes, qeReport.mrSigner, qeReport.isvProdId, qeReport.isvSvn
        );
    }

    function verifyQeReportData(bytes memory qeReportData, bytes memory attestationKey, bytes memory qeAuthData)
        internal
        pure
        returns (bool)
    {
        bytes32 expectedHash = bytes32(qeReportData);
        bytes memory preimage = abi.encodePacked(attestationKey, qeAuthData);
        bytes32 computedHash = sha256(preimage);
        return expectedHash == computedHash;
    }

    function attestationVerification(
        bytes memory rawQeReport,
        bytes memory qeSignature,
        bytes memory pckPubkey,
        bytes memory signedAttestationData,
        bytes memory attestationSignature,
        bytes memory attestationKey
    ) internal view returns (bool) {
        bool qeReportVerified = P256Verifier.ecdsaVerify(sha256(rawQeReport), qeSignature, pckPubkey);
        if (!qeReportVerified) {
            return false;
        }
        bool attestationVerified =
            P256Verifier.ecdsaVerify(sha256(signedAttestationData), attestationSignature, attestationKey);
        return attestationVerified;
    }

    function convergeTcbStatusWithQeTcbStatus(EnclaveIdTcbStatus qeTcbStatus, TCBStatus tcbStatus)
        internal
        pure
        returns (TCBStatus convergedStatus)
    {
        // https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L271-L312
        if (qeTcbStatus == EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE) {
            if (tcbStatus == TCBStatus.OK || tcbStatus == TCBStatus.TCB_SW_HARDENING_NEEDED) {
                convergedStatus = TCBStatus.TCB_OUT_OF_DATE;
            }
            if (
                tcbStatus == TCBStatus.TCB_CONFIGURATION_NEEDED
                    || tcbStatus == TCBStatus.TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED
            ) {
                convergedStatus = TCBStatus.TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
            }
        } else {
            convergedStatus = tcbStatus;
        }
    }

    function serializeOutput(Output memory output) internal pure returns (bytes memory) {
        return abi.encodePacked(
            output.quoteVersion, 
            output.tee, 
            output.tcbStatus, 
            output.fmspcBytes, 
            output.quoteBody, 
            output.advisoryIDs.length > 0 ? abi.encode(output.advisoryIDs) : bytes("")
        );
    }

    function checkCollateralHashes(uint256 offset, bytes calldata zkOutput) internal view returns (bool, bytes memory) {
        string memory mismatchMessage = "collateral mismatch";
        uint64 timestamp = uint64(bytes8(zkOutput[offset:offset + 8]));
        bytes32 rootCaHash = bytes32(zkOutput[offset + 72:offset + 104]);
        bytes32 tcbSigningHash = bytes32(zkOutput[offset + 104:offset + 136]);
        bytes32 rootCaCrlHash = bytes32(zkOutput[offset + 136:offset + 168]);
        bytes32 pckCrlHash = bytes32(zkOutput[offset + 168:offset + 200]);

        (bool tcbSigningFound, bytes32 expectedTcbSigningHash) = pccsRouter.getCertHash(CA.SIGNING);
        if (!tcbSigningFound || tcbSigningHash != expectedTcbSigningHash) {
            return (false, bytes(mismatchMessage));
        }
        (bool rootCaFound, bytes32 expectedRootCaHash) = pccsRouter.getCertHash(CA.ROOT);
        if (!rootCaFound || rootCaHash != expectedRootCaHash) {
            return (false, bytes(mismatchMessage));
        }
        (bool rootCrlFound, bytes32 expectedRootCrlHash) = pccsRouter.getCrlHash(CA.ROOT);
        if (!rootCrlFound || rootCaCrlHash != expectedRootCrlHash) {
            return (false, bytes(mismatchMessage));
        }

        // use low level calls for PCK CRLs, because we don't know which one of the CAs is used
        // to verify the quote
        // we can catch reverts here, and consider it a valid quote as long as:
        // - one of the PCK CAs has a CRL stored on-chain
        // - the hash of the on-chain CRL matches with the CRL hash in the zkOutput

        (bool platformSuccess, bytes memory platformRet) =
            address(pccsRouter).staticcall(abi.encodeWithSelector(IPCCSRouter.getCrlHashWithTimestamp.selector, CA.PLATFORM, timestamp));

        (bool processorSuccess, bytes memory processorRet) =
            address(pccsRouter).staticcall(abi.encodeWithSelector(IPCCSRouter.getCrlHashWithTimestamp.selector, CA.PROCESSOR, timestamp));

        bytes32 expectedPlatformCrlHash;
        bytes32 expectedProcessorCrlHash;
        if (platformSuccess) {
            expectedPlatformCrlHash = abi.decode(platformRet, (bytes32));
        } else if (processorSuccess) {
            expectedProcessorCrlHash = abi.decode(processorRet, (bytes32));
        } else {
            // Both Processor and Platform PCKs not found
            return (false, bytes(mismatchMessage));
        }

        bool crlHashMatched = pckCrlHash == expectedPlatformCrlHash || pckCrlHash == expectedProcessorCrlHash;
        return (crlHashMatched, crlHashMatched ? bytes("") : bytes(mismatchMessage));
    }
}
