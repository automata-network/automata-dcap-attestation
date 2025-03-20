<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Automata DCAP Attestation
[![Automata DCAP Attestation](https://img.shields.io/badge/Power%20By-Automata-orange.svg)](https://github.com/automata-network)

## Table of Contents
- [Summary](#summary)
- [Automata DCAP Attestation on EVM](#automata-dcap-attestation-on-evm)
- [Automata DCAP Attestation on Solana](#automata-dcap-attestation-on-solana)

---

## Summary

This repo serves as a code base for the Intel Data Center Attestation Primitive (DCAP) Web3-based Quote Verification program for both EVM and Solana.

Currently on the EVM, users can verify DCAP quotes with either full on-chain execution or using SNARK proofs by executing [DCAP zkVM Programs](https://github.com/automata-network/tdx-attestation-sdk/tree/main/zk) on zkVMs, such as RiscZero or Succinct SP1. We plan to add support for more zkVMs in the future.

The Solana program currently only supports SNARK proofs verification.

### zkProgram Identifiers

These identifiers are a required parameter for SNARK proof verifications, to show that the proofs are generated by the intended zkVM Program.

The [ImageID](https://dev.risczero.com/terminology#image-id) currently for the DCAP RiscZero Guest Program is 0xd6c3b4b08fa163dd44f89125f97223f6f7163e3f0f62e360d707adab8f6b7799.

The [VKEY](https://docs.succinct.xyz/verification/onchain/solidity-sdk.html?#finding-your-program-vkey) currently for the DCAP SP1 Program is
0x0036efd519bb371b29a40322e40031833716e9441c6907f8aefc5e52ceebc9a6.

---

## Automata DCAP Attestation on EVM

It consists of three smart contracts:

- PCCS Router: A central contract to read collaterals from [`automata-on-chain-pccs`](https://github.com/automata-network/automata-on-chain-pccs)

- Automata DCAP Attestation: This is the entrypoint contract for users to submit a quote to be verified. This contract parses the Quote header to identify the version, which then forwards the quote to the respective QuoteVerifier contract. 

- Quote Verifier(s): This contract provides the full implementation to verify a given quote specific to its version. This contract is intended to be called only from the Automata DCAP Attestation contract.

### On-Chain vs SNARK Attestations

Automata DCAP Attestation contract implements two attestation methods available to users. Here is a quick comparison:

|  | On-Chain | Groth16 Proof Verification with RiscZero v1.2.1 | Groth16 Proof Verification with SP1 V4 | Plonk Proof Verification with SP1 V4| 
| --- | --- | --- | --- | --- |
| Quote Verification Time | Instant | Proving takes <2 minutes, instant verification | Proving takes ~3 minutes, instant verification  | Proving takes ~5 minutes, instant verification |
| Gas Cost | ~4-5M gas (varies by collateral size) | 360k gas | 333k gas | 419k gas |
| Execution | Runs fully on-chain | Execution proven by remote prover Bonsai | Execution proven by the SP1 Network | Execution proven by the SP1 Network |

### Deployment

#### Testnet

| Contract | Network | Address |
| --- | --- | --- |
| `PCCSRouter.sol` | Automata Testnet | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://explorer-testnet.ata.network/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
|  | Ethereum Sepolia | [0xe20C4d54afBbea5123728d5b7dAcD9CB3c65C39a](https://sepolia.etherscan.io/address/0xe20C4d54afBbea5123728d5b7dAcD9CB3c65C39a) |
|  | Ethereum Holesky | [0xe20C4d54afBbea5123728d5b7dAcD9CB3c65C39a](https://holesky.etherscan.io/address/0xe20C4d54afBbea5123728d5b7dAcD9CB3c65C39a) |
|  | Base Sepolia | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://sepolia.basescan.org/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
|  | OP Sepolia | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://sepolia-optimism.etherscan.io/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
|  | World Sepolia | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://worldchain-sepolia.explorer.alchemy.com/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
|  | Arbitrum Sepolia | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://sepolia.arbiscan.io/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
| `AutomataDcapAttestationFee.sol` | Automata Testnet | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://explorer-testnet.ata.network/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
|  | Ethereum Sepolia | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://sepolia.etherscan.io/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
|  | Ethereum Holesky | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://holesky.etherscan.io/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
|  | Base Sepolia | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://sepolia.basescan.org/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
|  | OP Sepolia | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://sepolia-optimism.etherscan.io/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
|  | Arbitrum Sepolia | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://sepolia.arbiscan.io/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
| `V3QuoteVerifier.sol` | Automata Testnet | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://explorer-testnet.ata.network/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
|  | Ethereum Sepolia | [0x816ADa3B63F3c643fb04152eA32B58Db89aadd89](https://sepolia.etherscan.io/address/0x816ADa3B63F3c643fb04152eA32B58Db89aadd89) |
|  | Ethereum Holesky | [0x816ADa3B63F3c643fb04152eA32B58Db89aadd89](https://holesky.etherscan.io/address/0x816ADa3B63F3c643fb04152eA32B58Db89aadd89) |
|  | Base Sepolia | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://sepolia.basescan.org/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
|  | OP Sepolia | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://sepolia-optimism.etherscan.io/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
|  | World Sepolia | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://worldchain-sepolia.explorer.alchemy.com/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
|  | Arbitrum Sepolia | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://sepolia.arbiscan.io/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
| `V4QuoteVerifier.sol` | Automata Testnet | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://explorer-testnet.ata.network/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) |
|  | Ethereum Sepolia | [0x1a9E873C041F566fCBAdbD9e1358095b7Ea12AA8](https://sepolia.etherscan.io/address/0x1a9E873C041F566fCBAdbD9e1358095b7Ea12AA8) |
|  | Ethereum Holesky | [0x1a9E873C041F566fCBAdbD9e1358095b7Ea12AA8](https://holesky.etherscan.io/address/0x1a9E873C041F566fCBAdbD9e1358095b7Ea12AA8) |
|  | Base Sepolia | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://sepolia.basescan.org/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) |
|  | OP Sepolia | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://sepolia-optimism.etherscan.io/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) |
|  | Arbitrum Sepolia | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://sepolia.arbiscan.io/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) |


<!-- |  | World Sepolia | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://worldchain-sepolia.explorer.alchemy.com/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) | -->

#### Mainnet

| Contract | Network | Address |
| --- | --- | --- |
| `PCCSRouter.sol` | Automata Mainnet | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://explorer.ata.network/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
|  | Base Mainnet | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://basescan.org/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
|  | OP Mainnet | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://optimistic.etherscan.io/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
|  | World Mainnet | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://worldchain-mainnet.explorer.alchemy.com/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
|  | Arbitrum Mainnet | [0x0d089B3fA00CBAD0a5098025519e9e4620622acF](https://arbiscan.io/address/0x0d089B3fA00CBAD0a5098025519e9e4620622acF) |
| `AutomataDcapAttestationFee.sol` | Automata Mainnet | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://explorer.ata.network/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
|  | Base Mainnet | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://basescan.org/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
|  | OP Mainnet | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://optimistic.etherscan.io/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
|  | World Mainnet | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://worldchain-mainnet.explorer.alchemy.com/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
|  | Arbitrum Mainnet | [0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF](https://arbiscan.io/address/0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF) |
| `V3QuoteVerifier.sol` | Automata Mainnet | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://explorer.ata.network/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
|  | Base Mainnet | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://basescan.org/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
|  | OP Mainnet | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://optimistic.etherscan.io/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
|  | World Mainnet | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://worldchain-mainnet.explorer.alchemy.com/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
|  | Arbitrum Mainnet | [0x69523d25E25e5c78d828Df90459b75F189D40Cf7](https://arbiscan.io/address/0x69523d25E25e5c78d828Df90459b75F189D40Cf7) |
| `V4QuoteVerifier.sol` | Automata Mainnet | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://explorer.ata.network/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) |
|  | Base Mainnet | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://basescan.org/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) |
|  | OP Mainnet | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://optimistic.etherscan.io/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) |
|  | World Mainnet | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://worldchain-mainnet.explorer.alchemy.com/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) |
|  | Arbitrum Mainnet | [0xD34Cf419AF06629e158DB5F67541AaF2230290FB](https://arbiscan.io/address/0xD34Cf419AF06629e158DB5F67541AaF2230290FB) |

<!-- |  | Ethereum Mainnet | [0xC86EE37Ee5030B9fF737F3E71f7611Abf5dfD9B7](https://etherscan.io/address/0xC86EE37Ee5030B9fF737F3E71f7611Abf5dfD9B7) | -->


---

## Automata DCAP Attestation on Solana

### Overview

The following diagram illustrates an overview of the execution flow of the DCAP Solana Program.

![DCAP Solana Diagram](./solana/docs/images/DCAP%20Solana%20Diagram.jpg)

1. Invokes the `CreateDcapOutputAccount` instruction on the DCAP Program.
2. Reads the current count from DCAP Counter, which is used as seed to derive the address of the `VerifiedOutput` PDA.
3. Writes data to the `VerifiedOutput` PDA.
4. Increments the current count in DCAP Counter, which completes the `CreateDcapOutputAccount` instruction.
5. Invokes the `VerifyDcapProof` instruction on the DCAP Program.
6. Reads the output from the provided `VerifiedOutput` PDA address.
7. The output is pre-processed and converted into a Groth16 public input, then submitted along with the proofs to be verified with the corresponding zkVM verifier program.
8. Updates the data in `VerifiedOutput` PDA to indicate the status showing successful verification.
9. Downstream programs consume the data directly from the `VerifiedOutput` PDA.

### zkVM Verifier Programs

Depending on which zkVM programs that the user has chosen, the Automata DCAP Solana Program sends the processed `VerifiedOutput` along with proofs to one of the following programs:

- [RiscZero Groth16 Verifier](https://github.com/risc0/risc0-solana/blob/main/solana-verifier/programs/groth_16_verifier/src/lib.rs), this is a general-purpose Groth16 Verifier built by RiscZero that can be called by any Solana programs to perform Groth16 Verifications.

- [DCAP SP1 Solana Program](./solana/programs/dcap-sp1-solana-program/), this is a wrapper verifier program to be called only by the Automata DCAP Solana Program because it hardcodes the vkey. This program imports the [SP1 Solana Library](https://github.com/succinctlabs/sp1-solana/blob/master/example/program/src/lib.rs).

### Deployment

The DCAP Solana Program and Counter account have both been deployed to `devnet` at:

- DCAP Program: `DcapE9GZZ2KSu6udeW1pVdmqBAHP9NMBLBrxUUYdw1Qk`
- DCAP Counter: `DcapH8Bt1y6MQHE1hR2Rp1WEBeWfog2Kh9UxtG8UMaNu`