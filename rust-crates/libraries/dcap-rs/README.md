<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Automata DCAP Rust Implementation
[![Automata DCAP Rust Implementation](https://img.shields.io/badge/Power%20By-Automata-orange.svg)](https://github.com/automata-network)

Intel Data Center Attestation Primitives Quote Verification Library (DCAP QVL) implemented in pure Rust. 

This library can be integrated into zkVM programs that provide users the ability to attest DCAP quotes directly on-chain, by publishing and verifying ZK SNARK proofs in the [AutomataDCAPAttestation](https://github.com/automata-network/automata-dcap-attestation) contract.

This library supports verification of the following quotes:
-   V3 SGX Quotes
-   V4 TDX and SGX Quotes
-   V5 TDX and SGX Quotes

## zkVM Patches

zkVM programs provide patches, which are simply modified Rust crates that can help reducing execution cycle costs in the VM.

We have tested `dcap-rs` with both RiscZero and SP1 zkVMs, and we would happily work with more zkVMs in the future.

Read the section(s) below to learn about how patches can be applied towards corresponding zkVM programs.

### RiscZero Accelerators

Patches applied: 
- `crypto-bigint` 
- `sha2`
- `p256`

Make sure to include the following patches into your Guest's `cargo.toml`.

```
[patch.crates-io]
sha2 = { git = "https://github.com/risc0/RustCrypto-hashes", tag = "sha2-v0.10.6-risczero.0" }
crypto-bigint = { git = "https://github.com/risc0/RustCrypto-crypto-bigint", tag = "v0.5.2-risczero.0" }
p256 = { git = "https://github.com/risc0/RustCrypto-elliptic-curves", tag = "p256/v0.13.2-risczero.1" }
```

Click [here](https://dev.risczero.com/api/zkvm/acceleration) to learn more about RiscZero accelerators.

### SP1 Precompiles

Patches applied: 
- `crypto-bigint`
- `sha2`
- `p256`

Make sure to include the following patches into your workspace `cargo.toml`.

```
[patch.crates-io]
sha2 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", branch = "patch-sha2-v0.10.8" }
crypto-bigint = { git = "https://github.com/sp1-patches/RustCrypto-bigint", branch = "patch-v0.5.5" }
p256 = { git = "https://github.com/sp1-patches/elliptic-curves", tag = "patch-p256-13.2-sp1-5.0.0" }
```

Click [here](https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompiles) to learn more about SP1 Precompiles.

### Pico zkVM Patches

Patches applied: 
- `crypto-bigint`
- `sha2`

Make sure to include the following patches into your workspace `cargo.toml`.

```
[patch.crates-io]
sha2 = { git = "https://github.com/brevis-network/hashes", branch = "pico-patch-v1.0.1-sha2-v0.10.8" }
crypto-bigint = { git = "  https://github.com/brevis-network/crypto-bigint", branch = "pico-patch-v1.0.0-bigint-v0.6.0" }
```

Click [here](https://pico-docs.brevis.network/integrating-coprocessors/function-level.html#list-of-patches) to learn more about Pico zkVM Patches.