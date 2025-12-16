<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Automata DCAP Attestation

Web3-based Intel DCAP (Data Center Attestation Primitives) Quote Verification for EVM and Solana.

## Features

- **Onchain Verification** - Full quote verification executed directly onchain (EVM)
- **zkVM Support** - SNARK proof verification via RISC Zero, SP1, and Pico
- **Multi-Platform** - EVM smart contracts and Solana programs
- **Comprehensive Tooling** - Rust libraries and CLI for quote verification, collateral management, and proof generation

## Table of Contents

- [Deployment Info](#deployment-info)
- [Getting Started](#getting-started)
  - [Rust Workspace](#rust-workspace)
  - [EVM Integration](#evm-integration)
  - [Solana Integration](#solana-integration)
- [Architecture](#architecture)
  - [EVM Contracts](#evm-contracts)
  - [Verification Methods](#verification-methods)
- [Security Audits](#security-audits)
- [License](#license)

---

## Deployment Info

Each release contains deployment information including zkVM Program Identifiers and contract addresses.

| Version | Release Notes |
|---------|---------------|
| **Current (v1.1)** | [View](./releases/v1.1/NOTE.md) |
| v1.0 | [View](./releases/v1.0/NOTE.md) |

---

## Getting Started

### Rust Workspace

The Rust workspace provides libraries for DCAP quote verification and a unified CLI tool.

**Key Libraries:**
- `dcap-rs` - Pure Rust implementation of Intel's DCAP QVL
- `automata-dcap-zkvm` - zkVM proof generation (RISC Zero, SP1, Pico)
- `automata-dcap-verifier` - High-level verification APIs

```bash
# Clone the repository
git clone https://github.com/automata-network/automata-dcap-attestation.git --recurse-submodules

# Build and run CLI
cd rust-crates
cargo build --release
```

See the [Rust workspace documentation](./rust-crates/README.md) for detailed usage.

### EVM Integration

Install via Foundry or npm:

```bash
# Foundry
forge install automata-network/automata-dcap-attestation

# npm
npm install @automata-network/automata-dcap-attestation
```

See the [EVM integration guide](./evm/README.md) for contract integration and deployment.

### Solana Integration

> **Note:** The Solana programs are currently in development and available for localnet testing only.

See the [Solana DCAP framework documentation](./solana/automata-dcap-framework/README.md) for architecture details and testing instructions.

---

## Architecture

### EVM Contracts

| Contract | Description |
|----------|-------------|
| **PCCS Router** | Central contract to read collaterals from [automata-on-chain-pccs](https://github.com/automata-network/automata-on-chain-pccs) |
| **Automata DCAP Attestation** | Entrypoint for quote verification; routes to version-specific verifiers |
| **Quote Verifiers** | Version-specific verification logic (V3, V4, V5) |

### Verification Methods

|  | Onchain | RiscZero Groth16 | SP1 Groth16 | SP1 Plonk |
|---|----------|------------------|-------------|-----------|
| **Proving Time** | Instant | <1 min | <30s | <2 min |
| **Gas Cost** | ~4-5M gas | 522k gas | 493k gas | 569k gas |
| **Execution** | Fully onchain | Boundless prover | SP1 Prover Network | SP1 Prover Network |

*Onchain gas: ~4M with RIP-7212 precompile, ~5M without*

---

## Security Audits

| Date | Auditor | Scope | Report |
|------|---------|-------|--------|
| Feb 2025 | Trail of Bits | Automata Onchain PCCS & Automata DCAP Attestation EVM (v1.0) | [View](https://github.com/trailofbits/publications/blob/master/reviews/2025-02-automata-dcap-attestation-onchain-pccs-securityreview.pdf) |
| Oct 2025 | OpenZeppelin | Jovay TEE Verifier (uses Automata DCAP Attestation) | [View](https://github.com/jovaynetwork/jovay-docs/blob/main/security-reports/202510/Jovay-TEE-Verifier-Audit-2025.10.pdf) |

> [!NOTE]
> The OpenZeppelin audit identified a PCCS Router timestamp validity issue, which [has been fixed](https://github.com/automata-network/automata-dcap-attestation/pull/52/commits/62466820089a124ac872e6cedbae2a4cdae416b0) in v1.1.

> [!CAUTION]
> The Solana programs are not audited for production use.

---

## License

MIT - See [LICENSE](./LICENSE) for details.
