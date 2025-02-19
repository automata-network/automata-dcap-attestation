# Automata DCAP Solana Program Guide

This repository includes the implementations for: 

- DCAP Attestation Solana Program

and

- DCAP Attestation Solana Rust Client

To interact with the program, you must install the following on your machine:

- [Rust](https://www.rust-lang.org/tools/install)

- [Solana CLI](https://solana.com/docs/intro/installation) 👉 `v2.1.6` or above

**Note**: You do not need to install Anchor for this program.

If this is your first time using Solana on your machine, we recommend checking out the [Solana CLI Basics](https://solana.com/docs/intro/installation#solana-cli-basics) guide.

---

## Build, Test and Deploy the Program

Build the program with:

```bash
cargo build-sbf
```

Run all tests with:

```bash
cargo test-sbf
```

Cargo runs all tests in parallel, and it can get messy with your terminal filling up with logs that can be hard to track.

We recommend running each test individually.

```bash
cargo test-sbf <insert-test-name>
```

To deploy the program yourself, you must first generate the keypairs for both the program and counter accounts. This requires changes to be made on the constant values at `automata-dcap-program/src/lib.rs` and `automata-dcap-client/src/lib.rs`.

Run the command below to deploy the program:

```bash
solana program deploy --program-id <keypair-path> --url [`devnet` || `mainnet-beta` || `localhost`]
```

After deployment of the program, you would need to create the `Counter` account.

```bash
SOLANA_RPC_URL=<url_string> cargo run --bin counter
```

---

To learn more about integrating the client into your Rust code, click [here](./automata-dcap-client/README.md) to read the guide.