# Automata DCAP Attestation (EVM)

## Release Note `evm-v1.0.0`

A production-ready release of the Automata DCAP Attestation EVM Solidity Smart Contracts. 

This release only applies to source code located in the `/evm` directory.

### What's Changed?

- The contract has been fully audited by Trail of Bits.  
  [🔗 View the full audit report](https://github.com/trailofbits/publications/blob/master/reviews/2025-02-automata-dcap-attestation-onchain-pccs-securityreview.pdf)

- Integrated [RIP-7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md) for cheaper secp256r1 ECDSA verification on supported networks.

- TEE Type values are encoded and handled in little-endian order.

- Intel PCK Certificate Chain must now contain exactly 3 X509 Certificates.

- PCCS Router checks the validity window before loading the full collateral data, which prevents wasting gas on loading expired collaterals into memory.

- Checks Attestation Timestamp for Quote Verifications with ZK.

- Checks `TcbInfo` and `QEIdentity` for Quote Verification with ZK.

- Event logs are emitted for all state-changing functions.

---

[👉 Full Changelog (`v0.1.1...evm-v1.0.0`)](https://github.com/automata-network/automata-dcap-attestation/compare/v0.1.1...evm-v1.0.0)