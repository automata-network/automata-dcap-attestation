<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Automata DCAP Rust Library Workspace

## Table of Contents
- [Summary](#summary)
- [Workspace Layout](#workspace-layout)
- [Deployment Info](#deployment-info)
- [Related Branches](#related-branches)

---

## Summary

This workspace provides a comprehensive toolkit for Intel DCAP (Data Center Attestation Primitives) quote verification and attestation, featuring both library components for integration and a CLI tool for testing and examples.

**For Developers:** The project offers several Rust libraries that can be integrated directly into your applications:
- **dcap-rs**: Pure Rust implementation of Intel's DCAP Quote Verification Library (QVL), supporting V3 SGX and V4 TDX/SGX quotes
- **pccs-reader**: Reader library for decoding collaterals from Automata Onchain PCCS and detecting missing collaterals
- **automata-dcap-qpl**: Quote Provider Library wrapper for fetching collaterals from various sources
- **automata-dcap-zkvm**: zkVM proof generation libraries with support for RISC Zero, SP1, and Pico platforms
- **automata-dcap-verifier**: High-level verification APIs for both onchain and zkVM-based attestation

**CLI Tool:** A unified `automata-dcap` binary is provided as a practical example of library integration. It demonstrates quote verification, collateral management, network operations, and zkVM proof generation workflows.

**Supported zkVM Platforms:**
- **RISC Zero**: Full CLI and contract support (Groth16 proofs via Bonsai or Boundless)
- **SP1**: Full CLI and contract support (Groth16 and Plonk proofs via SP1 Network)
- **Pico**: CLI and contract support for local proving only. (Brevis has not released a remote prover yet)

## Workspace Layout

This repository uses a **unified Rust workspace** with smart defaults:

```
/Cargo.toml                         # Single workspace root
├── apps/cli/                       # Unified automata-dcap CLI
├── libraries/*                     # Support crates (8 crates)
└── contracts/                      # Minimal Solidity interfaces
```

### Package Organization

**Applications:**
- `apps/cli`: Unified `automata-dcap` CLI (quote verification, collateral detection, network management, zkVM proof generation)

**Core Libraries:**
- `crates/dcap-rs`: Pure Rust implementation of Intel's DCAP Quote Verification Library (QVL) for V3 SGX and V4 TDX/SGX quotes
- `crates/verifier`: High-level verification APIs that orchestrate quote verification workflows for both onchain and zkVM-based attestation
- `crates/zkvm`: zkVM proof generation framework with unified trait-based architecture supporting RISC Zero, SP1, and Pico platforms

**Support Libraries:**
- `crates/pccs-reader`: Reader for decoding collaterals from Automata Onchain PCCS and detecting missing collaterals for a given quote
- `crates/qpl`: Quote Provider Library (QPL) wrapper for fetching collaterals from Intel PCS, local PCCS, or Automata Onchain PCCS
- `crates/network-registry`: Network configuration registry managing deployment addresses and contract ABIs across multiple chains and versions
- `crates/utils`: Common utilities including version-aware type generation and helper functions shared across the workspace
- `crates/bindings`: Auto-generated Rust bindings for EVM contract interfaces (regenerated via build script)

**Contract Interfaces:**
- `contracts/`: Solidity contract interfaces for Automata Onchain PCCS and Automata DCAP Attestation to generate Rust bindings

### Regenerating EVM bindings

Whenever the Solidity ABI changes, regenerate the bindings from the repository root:

```bash
AUTOMATA_UPDATE_BINDINGS=1 cargo build -p automata-dcap-evm-bindings
```

This runs `forge build` and writes fresh bindings into `crates/dcap-evm-bindings/src/bindings`.
To enforce drift checks locally or in CI, run:

```bash
scripts/check-bindings.sh
```

### CLI Usage

The CLI has been implemented for users to quickly perform actions such as: verifying quotes onchain or with ZK proofs, ZK Proof generations, and collateral detections for a specified quote.

Read [this](./apps/cli/README.md) documentation to learn more about its usage.

---

## Related Branches

Automata Onchain PCCS Solidity Code:
- https://github.com/automata-network/automata-on-chain-pccs

Automata SGX and TDX Rust SDKs:
- https://github.com/automata-network/automata-sgx-sdk
- https://github.com/automata-network/tdx-attestation-sdk