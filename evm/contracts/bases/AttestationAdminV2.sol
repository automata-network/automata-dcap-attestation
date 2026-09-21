// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Import shared types, never inherit the legacy entrypoint or its registry.
import {ZkCoProcessorType} from "../AttestationEntrypointBase.sol";
import {IQuoteVerifier} from "../interfaces/IQuoteVerifier.sol";
import {Header} from "../types/CommonStruct.sol";
import {BELE} from "../utils/BELE.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {FeeManagerBase} from "./FeeManagerBase.sol";

abstract contract AttestationAdminV2 is Ownable, FeeManagerBase {
    address internal constant FROZEN = address(0xdead);
    mapping(uint16 => IQuoteVerifier) public quoteVerifiers;
    mapping(ZkCoProcessorType => mapping(bytes4 => address)) internal _proofRoutes;

    error ZK_Route_Frozen(ZkCoProcessorType backend, bytes4 selector);
    error Cannot_Remove_ProgramIdentifier(ZkCoProcessorType backend, bytes32 identifier);
    event QuoteVerifierUpdated(uint16 indexed version);
    event ZkRouteAdded(ZkCoProcessorType indexed backend, bytes4 selector, address verifier);
    event ZkRouteFrozen(ZkCoProcessorType indexed backend, bytes4 selector);

    constructor(address owner) {
        _initializeOwner(owner);
    }

    modifier noneZkConfigCheck(ZkCoProcessorType backend) {
        require(backend != ZkCoProcessorType.None, "Cannot use None ZK Co-Processor");
        _;
    }

    function setBp(uint16 bp) public override onlyOwner {
        super.setBp(bp);
    }

    function withdraw(address beneficiary, uint256 amount) public override onlyOwner {
        super.withdraw(beneficiary, amount);
    }

    function setQuoteVerifier(address verifier) external onlyOwner {
        require(verifier.code.length != 0, "Quote verifier has no code");
        uint16 version = IQuoteVerifier(verifier).quoteVersion();
        require(version >= 3 && version <= 5, "Unsupported quote version");
        quoteVerifiers[version] = IQuoteVerifier(verifier);
        emit QuoteVerifierUpdated(version);
    }

    function addVerifyRoute(ZkCoProcessorType backend, bytes4 selector, address verifier)
        external
        onlyOwner
        noneZkConfigCheck(backend)
    {
        require(verifier.code.length != 0 && verifier != FROZEN, "ZK Verifier has no code");
        if (_proofRoutes[backend][selector] == FROZEN) revert ZK_Route_Frozen(backend, selector);
        _proofRoutes[backend][selector] = verifier;
        emit ZkRouteAdded(backend, selector, verifier);
    }

    function freezeVerifyRoute(ZkCoProcessorType backend, bytes4 selector)
        external
        onlyOwner
        noneZkConfigCheck(backend)
    {
        if (_proofRoutes[backend][selector] == FROZEN) {
            revert ZK_Route_Frozen(backend, selector);
        }
        _proofRoutes[backend][selector] = FROZEN;
        emit ZkRouteFrozen(backend, selector);
    }

    function _parseQuoteHeader(bytes calldata rawQuote) internal pure returns (bool success, Header memory header) {
        success = rawQuote.length >= 48;
        if (success) {
            header = Header({
                version: uint16(BELE.leBytesToBeUint(rawQuote[0:2])),
                attestationKeyType: bytes2(rawQuote[2:4]),
                teeType: bytes4(rawQuote[4:8]),
                qeSvn: bytes2(rawQuote[8:10]),
                pceSvn: bytes2(rawQuote[10:12]),
                qeVendorId: bytes16(rawQuote[12:28]),
                userData: bytes20(rawQuote[28:48])
            });
        }
    }
}
