# RISC Zero V2 guest build and local execution

Keep `risc0-build`, guest/host `risc0-zkvm`, `cargo-risczero` and `r0vm` at
3.0.3. The driver and guest lockfiles also freeze their transitive dependencies;
do not upgrade SDKs or change the universal-verifier family to fix a local build.

## Toolchain

The tested Linux ARM64 installation is:

```text
rzup rust: 1.88.0+de85b1d3d7f
rustc: 1.88.0-dev (de85b1d3d 2025-06-26), LLVM 20.1.5
cargo-risczero: 3.0.3
r0vm: 3.0.3
```

Check it with `rzup show`, `rustc +risc0 --version`,
`cargo risczero --version` and `r0vm --version`.
The build driver also needs the separate Cargo 1.88.0 used by SP1:

```sh
rustup toolchain install 1.88.0 --profile minimal --no-self-update
cargo +1.88.0 --version
```

`risc0-build` selects the compiler from rzup but invokes plain Cargo and removes
`RUSTUP_TOOLCHAIN` from its child environment. The driver therefore prepends the
pinned Cargo's directory to its child PATH, leaving the system default unchanged.
It also sets `RISC0_BUILD_LOCKED=1`: the outer Cargo's `--locked` alone would not
lock the guest build. Newer Cargo can emit flags unsupported by Rust 1.88.

The guest lockfile was resolved for Rust 1.88, then `ruint` was pinned to 1.17.0
to match the host and SP1. All four existing RISC Zero crypto-patch tags remain
unchanged. Normal builds must preserve the lockfile, not regenerate it.

## Build

From the repository root:

```sh
CARGO_BUILD_JOBS=2 cargo build --release --locked \
  --manifest-path rust-crates/libraries/zkvm/methods/risc0/Cargo.toml \
  --target-dir rust-crates/target
r0vm --elf rust-crates/libraries/zkvm/artifacts/v2.0/risc0.elf --id
```

The outputs are `zkvm/artifacts/v2.0/risc0.elf` and `risc0.image-id`. Despite its
historical `.elf` suffix, the former is the RISC Zero 3.x **combined user/kernel
program binary** produced by `embed_methods`, not a raw ELF. `file` reporting
`data` is expected. Compute its native ID using `r0vm --id` or
`risc0_zkvm::compute_image_id`; a SHA-256 file digest is not the image ID.
Old embedded artifacts and deployment configuration are untouched.

To repeat the build, use a new empty absolute target directory, explicitly set
`CARGO_TARGET_DIR` to it, and compare artifact hashes. A same-machine match does
not establish independent-machine/container reproducibility.

## Execute a real input

Use a complete V2 ABI input from `dcap_rs::v2::encode_guest_input_v2`, including
the signed quote, collateral and fixed verification timestamp:

```sh
CARGO_BUILD_JOBS=2 cargo run --locked \
  --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features risc0 --example risc0_v2_execute \
  --target-dir rust-crates/target -- \
  rust-crates/libraries/zkvm/artifacts/v2.0/risc0.elf /path/to/v2-input.bin --negative
```

The example requires local `r0vm` 3.0.3, rejects enabled `RISC0_DEV_MODE`, and
explicitly executes in a local subprocess. It never selects Bonsai or submits
a proving request. The subprocess needs local IPC/loopback access.

Successful execution must halt with status zero, match the native journal
byte-for-byte and pass the SDK's OutputV2 decoder. `--negative` also checks a
changed signed quote body and a timestamp before certificate validity. Only a
DCAP verification panic counts as rejection, not transport errors, arbitrary
faults or the 500-million-cycle session limit. Reported cycles are user cycles,
excluding continuation overhead and proof padding.

On memory-constrained Linux machines, the host example can be linked with
Rust's bundled LLD, as in the [SP1 instructions](../sp1/README.md#low-memory-host-linking),
using `--features risc0 --example risc0_v2_execute` instead. This is a host-only
setting; it does not alter the program binary or image ID.

Execution parity is not proof verification. Real receipts and verification
against the reused universal verifier remain release prerequisites; see
the [progress evidence](../../../../../docs/dcap-v2-progress.md).
