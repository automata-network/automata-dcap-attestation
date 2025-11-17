# Automata DCAP CLI

Command-line tool for Automata DCAP attestation workflows, including quote verification, collateral management, network operations, and zkVM proof generation.

## Table of Contents
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Global Options](#global-options)
- [Commands](#commands)
  - [Networks](#networks)
  - [Inspect](#inspect)
  - [QPL (Quote Provider Library)](#qpl-quote-provider-library)
  - [Verify](#verify)
  - [zkVM](#zkvm)
- [Environment Variables](#environment-variables)
- [Examples](#examples)

---

## Installation

Build the CLI from the workspace root:

```bash
cargo build --release -p automata-dcap-cli
```

The binary will be available at `target/release/automata-dcap`.

Optionally, install it globally:

```bash
cargo install --path apps/cli
```

## Quick Start

```bash
# List supported networks
automata-dcap networks

# Inspect a quote file
automata-dcap --quote-path <path-to-quote> inspect

# Check collateral status across all networks
automata-dcap qpl status

# Verify a quote onchain
automata-dcap \
  --network automata_testnet \
  --quote-path <path-to-quote> \
  verify onchain

# Generate a zkVM proof with RISC Zero
automata-dcap \
  --network automata_testnet \
  --quote-path <path-to-quote> \
  zkvm risc0 prove bonsai
```

---

## Global Options

These options can be used with any command:

| Option | Environment Variable | Description |
|--------|---------------------|-------------|
| `--network <NETWORK>` | `AUTOMATA_DCAP_NETWORK` | Network to use (e.g., `automata_testnet`, `eth_mainnet`) |
| `--rpc-url <URL>` | `AUTOMATA_DCAP_RPC_URL` | Override RPC URL (takes precedence over network's default RPC) |
| `--private-key <KEY>` | `AUTOMATA_DCAP_PRIVATE_KEY` | Private key for signing transactions (required for write operations) |
| `--quote-path <PATH>` | - | Path to quote file (can be binary or hex string) |
| `--quote-hex <HEX>` | - | Quote provided as hex string (alternative to `--quote-path`) |
| `--tcb-eval-number <NUM>` | - | TCB evaluation data number (uses standard if not provided) |
| `--dcap-version <VERSION>` | `AUTOMATA_DCAP_VERSION` | DCAP deployment version (`v1.0` or `v1.1`, defaults to `v1.1`) |

### Network Resolution

The CLI supports flexible network configuration:

- **Only `--network`**: Uses the network's default RPC endpoint
- **Only `--rpc-url`**: Auto-detects network from chain ID
- **Both `--network` and `--rpc-url`**: Validates that the RPC matches the network's chain ID
- **Neither**: Uses the default network (Automata Testnet)

---

## Commands

### Networks

List supported networks and their configuration.

```bash
automata-dcap networks [OPTIONS]
```

**Options:**
- `--filter <TYPE>` - Filter by network type: `mainnet`, `testnet`, or `all`

**Example:**
```bash
# List all supported networks
automata-dcap networks

# List only mainnet networks
automata-dcap networks --filter mainnet
```

---

### Inspect

Inspect and pretty-print quote and verified output structures.

```bash
automata-dcap inspect [OPTIONS]
```

**Options:**
- `--output-path <PATH>` - Path to verified output file
- `--output-hex <HEX>` - Verified output as hex string

**Note:** Use global `--quote-path` or `--quote-hex` to inspect quotes.

**Examples:**
```bash
# Inspect a quote
automata-dcap --quote-path <path-to-quote> inspect

# Inspect both quote and verified output
automata-dcap --quote-path <path-to-quote> inspect --output-path ./output.bin

# Inspect verified output only
automata-dcap inspect --output-hex 0x1234...
```

---

### QPL (Quote Provider Library)

Manage and monitor collaterals onchain.

#### Status

Check PCCS collateral status across networks (no quote required).

```bash
automata-dcap qpl status [OPTIONS]
```

**Options:**
- `--filter <TYPE>` - Filter networks: `mainnet`, `testnet`, or `all` (default: `all`)

**Example:**
```bash
# Check collateral status on all networks
automata-dcap qpl status

# Check only testnet collaterals
automata-dcap qpl status --filter testnet
```

#### Check

Inspect which collaterals are missing for a specific quote.

```bash
automata-dcap --quote-path <PATH> qpl check [OPTIONS]
```

**Options:**
- `--all-networks <FILTER>` - Check across multiple networks: `mainnet`, `testnet`, or `all`

**Examples:**
```bash
# Check collaterals for a quote on the default network
automata-dcap --network automata_testnet --quote-path <path-to-quote> qpl check

# Check collaterals across all networks
automata-dcap --quote-path <path-to-quote> qpl check --all-networks all

# Check collaterals across all mainnet networks
automata-dcap --quote-path <path-to-quote> qpl check --all-networks mainnet
```

#### Function

Call specific QPL functions to fetch collateral data.

**Available functions:**
- `sgx_ql_get_quote_config` - Fetch quote configuration
- `sgx_ql_get_quote_verification_collateral` - Fetch SGX verification collateral
- `tdx_ql_get_quote_verification_collateral` - Fetch TDX verification collateral
- `sgx_ql_get_qve_identity` - Fetch QVE identity
- `sgx_ql_get_root_ca_crl` - Fetch root CA CRL

**Example:**
```bash
# Fetch SGX quote verification collateral
automata-dcap qpl function sgx_ql_get_quote_verification_collateral \
  --source all \
  --fmspc 00906ED50000 \
  --pck-ca platform \
  --collateral-version v3 \
  --pccs-url https://api.trustedservices.intel.com
```

**Common QPL Function Options:**
- `--source <SOURCE>` - Data source: `azure`, `local`, or `all` (default: `all`)
- `--collateral-version <VERSION>` - Collateral version (default: `v3`)
- `--pccs-url <URL>` - PCCS URL (default: Intel PCS)

---

### Verify

Verify quotes onchain or with ZK proofs.

#### Onchain Verification

Verify a quote directly using the Automata DCAP Attestation smart contract.

```bash
automata-dcap --quote-path <PATH> verify onchain
```

**Example:**
```bash
# Verify quote on Automata Testnet
automata-dcap \
  --network automata_testnet \
  --quote-path <path-to-quote> \
  verify onchain

# Verify quote on Ethereum Mainnet with custom RPC
automata-dcap \
  --network eth_mainnet \
  --rpc-url https://eth.llamarpc.com \
  --quote-path <path-to-quote> \
  verify onchain
```

#### ZK Proof Verification

Verify a quote using a zkVM proof.

```bash
automata-dcap verify zk [OPTIONS]
```

**Options (Artifact Mode):**
- `--artifact <PATH>` - Path to zkVM proof artifact JSON file

**Options (Manual Mode):**
- `--zkvm <TYPE>` - zkVM type: `risc0`, `sp1`, or `pico`
- `--journal <HEX_OR_PATH>` - Journal/output bytes (hex string or file path)
- `--proof <HEX_OR_PATH>` - Proof bytes (hex string or file path)
- `--program-id <HEX>` - Program identifier (32 bytes as hex string, optional)

**Examples:**
```bash
# Verify using artifact file (recommended)
automata-dcap \
  --network automata_testnet \
  verify zk --artifact ./proof_artifact.json

# Verify with manual arguments
automata-dcap \
  --network automata_testnet \
  verify zk \
  --zkvm risc0 \
  --journal ./journal.bin \
  --proof ./proof.bin \
  --program-id 0x1234...

# Verify with hex strings
automata-dcap \
  --network automata_testnet \
  verify zk \
  --zkvm sp1 \
  --journal 0x1234... \
  --proof 0x5678...
```

---

### zkVM

Generate zkVM proofs and utilities for supported zkVM platforms.

#### RISC Zero

```bash
automata-dcap zkvm risc0 <SUBCOMMAND>
```

**Available subcommands:**

##### `prove`
Generate a RISC Zero proof using Bonsai or Boundless proving services.

```bash
automata-dcap zkvm risc0 prove <bonsai|boundless> [OPTIONS]
```

**Bonsai Mode:**
```bash
automata-dcap \
  --network automata_testnet \
  --quote-path <path-to-quote> \
  zkvm risc0 prove bonsai \
  [--api-url <URL>] \
  [--api-key <KEY>] \
  [--output-path <PATH>]
```

Options:
- `--api-url <URL>` - Bonsai API URL (env: `BONSAI_API_URL`)
- `--api-key <KEY>` - Bonsai API Key (env: `BONSAI_API_KEY`)
- `--output-path <PATH>` - Save proof artifact as JSON

**Boundless Mode:**
```bash
automata-dcap \
  --network automata_testnet \
  --quote-path <path-to-quote> \
  zkvm risc0 prove boundless \
  [--boundless-rpc-url <URL>] \
  [--boundless-private-key <KEY>] \
  [--program-url <URL>] \
  [--proof-type <groth16|merkle>] \
  [--min-price <WEI>] \
  [--max-price <WEI>] \
  [--timeout <SECONDS>] \
  [--ramp-up-period <SECONDS>] \
  [--output-path <PATH>]
```

Options:
- `--boundless-rpc-url <URL>` - Boundless RPC URL (env: `BOUNDLESS_RPC_URL`)
- `--boundless-private-key <KEY>` - Wallet private key (env: `BOUNDLESS_PRIVATE_KEY`)
- `--program-url <URL>` - Guest ELF program URL (env: `BOUNDLESS_PROGRAM_URL`)
- `--proof-type <TYPE>` - Proof type: `groth16` or `merkle` (default: `groth16`)
- `--min-price <WEI>` - Minimum price in wei
- `--max-price <WEI>` - Maximum price in wei
- `--timeout <SECONDS>` - Timeout in seconds
- `--ramp-up-period <SECONDS>` - Ramp up period in seconds
- `--output-path <PATH>` - Save proof artifact as JSON

##### `image-id`
Display the Image ID (program identifier) for the RISC Zero guest program.

```bash
automata-dcap zkvm risc0 image-id
```

---

#### SP1

```bash
automata-dcap zkvm sp1 <SUBCOMMAND>
```

**Available subcommands:**

##### `prove`
Generate an SP1 proof using the SP1 Network.

```bash
automata-dcap \
  --network automata_testnet \
  --quote-path <path-to-quote> \
  zkvm sp1 prove \
  --sp1-private-key <KEY> \
  [--proof-system <groth16|plonk>] \
  [--network-prover-mode <hosted|reserved|auction>] \
  [--output-path <PATH>]
```

Options:
- `--sp1-private-key <KEY>` - SP1 Network Private Key (env: `SP1_NETWORK_PRIVATE_KEY`) **[required]**
- `-s, --proof-system <TYPE>` - Proof system: `groth16` or `plonk` (default: `groth16`)
- `-n, --network-prover-mode <MODE>` - Network prover mode: `hosted`, `reserved`, or `auction` (default: `auction`)
- `--output-path <PATH>` - Save proof artifact as JSON

##### `verifying-key`
Display the Verifying Key (program identifier) for the SP1 guest program.

```bash
automata-dcap zkvm sp1 verifying-key
```

---

#### Pico

```bash
automata-dcap zkvm pico <SUBCOMMAND>
```

**Available subcommands:**

##### `prove`
Generate a Pico proof (local proving only).

```bash
automata-dcap \
  --network automata_testnet \
  --quote-path <path-to-quote> \
  zkvm pico prove \
  [--artifacts-path <PATH>] \
  [--field-type <TYPE>] \
  [--output-path <PATH>]
```

Options:
- `--artifacts-path <PATH>` - Directory containing EVM proof artifacts (default: `./artifacts/`)
- `--field-type <TYPE>` - Field type for proving backend: `kb` (KoalaBear) or `bb` (BabyBear) (default: `kb`)
- `--output-path <PATH>` - Save proof artifact as JSON

##### `generate-evm-inputs`
Generate EVM contract inputs from Pico proof artifacts.

```bash
automata-dcap zkvm pico generate-evm-inputs --artifacts-path <PATH>
```

Options:
- `--artifacts-path <PATH>` - Directory containing EVM proof artifacts **[required]**

##### `program-id`
Display the Program ID (vkey hash) for the Pico guest program.

```bash
automata-dcap zkvm pico program-id
```

---

## Environment Variables

Configuration can be provided via environment variables or a `.env` file:

```bash
# Network configuration
export AUTOMATA_DCAP_NETWORK=automata_testnet
export AUTOMATA_DCAP_RPC_URL=https://rpc-testnet.ata.network
export AUTOMATA_DCAP_VERSION=v1.1

# Private key (for write operations)
export AUTOMATA_DCAP_PRIVATE_KEY=0x1234...

# RISC Zero (Bonsai)
export BONSAI_API_URL=https://api.bonsai.xyz
export BONSAI_API_KEY=your_api_key

# RISC Zero (Boundless)
export BOUNDLESS_RPC_URL=https://boundless.rpc.url
export BOUNDLESS_PRIVATE_KEY=0x1234...
export BOUNDLESS_PROGRAM_URL=https://program.url/elf

# SP1
export SP1_NETWORK_PRIVATE_KEY=0x1234...

# Logging
export RUST_LOG=info
```

Command-line arguments take precedence over environment variables.

---

## Examples

### End-to-End Workflow

```bash
# 1. Check if quote is supported on target network
automata-dcap \
  --network automata_testnet \
  --quote-path <path-to-quote> \
  qpl check

# 2. Generate a zkVM proof
automata-dcap \
  --network automata_testnet \
  --quote-path <path-to-quote> \
  zkvm risc0 prove bonsai --output-path ./proof_artifact.json

# 3. Verify the proof onchain
automata-dcap \
  --network automata_testnet \
  verify zk --artifact ./proof_artifact.json
```

### Multi-Network Collateral Check

```bash
# Check if a quote's collaterals are available across all mainnet deployments
automata-dcap \
  --quote-path <path-to-quote> \
  --dcap-version v1.1 \
  qpl check --all-networks mainnet
```

### Quote Inspection

```bash
# Parse and display quote structure
automata-dcap --quote-path <path-to-quote> inspect

# Inspect from hex string
automata-dcap --quote-hex 0x03000200... inspect
```

### Custom RPC Configuration

```bash
# Use custom RPC with auto-detection
automata-dcap \
  --rpc-url https://ethereum.publicnode.com \
  --quote-path <path-to-quote> \
  verify onchain

# Use custom RPC with explicit network (validates chain ID)
automata-dcap \
  --network eth_mainnet \
  --rpc-url https://ethereum.publicnode.com \
  --quote-path <path-to-quote> \
  verify onchain
```

### zkVM Program Identifiers

```bash
# Get RISC Zero Image ID
automata-dcap zkvm risc0 image-id

# Get SP1 Verifying Key
automata-dcap zkvm sp1 verifying-key

# Get Pico Program ID
automata-dcap zkvm pico program-id
```