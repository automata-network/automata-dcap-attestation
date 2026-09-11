# Pico V2 guest build

This driver retains Pico SDK/VM **v1.1.6**, KoalaBear and its existing proof
system. It does not use `cargo-pico`: that release hardcodes nightly-2024-11-27
and does not pass `--locked` to its inner Cargo build.

The replacement driver pins **nightly-2025-08-04** (rustc 1.91.0-nightly,
f34ba774c), with `rust-src`. It preserves v1.1.6's:

- target `riscv32im-risc0-zkvm-elf`;
- `build-std=alloc,core,proc_macro,panic_abort,std` and
  `build-std-features=compiler-builtins-mem`;
- `passes=lower-atomic`, `-Ttext=0x00200800`, `--fatal-warnings` and `panic=abort`.

The inner Cargo build is explicitly `--locked` and has an isolated target
directory. Host compiler/flag overrides are cleared. A successful executable is
checked for an ELF32 little-endian RISC-V header before publishing `pico.elf`.
Failed builds do not publish an ELF; any prior artifact must not be mistaken for
a successful new build. Old embedded ELFs and deployment configuration are untouched.

## Install and build

From the repository root:

```sh
rustup toolchain install nightly-2025-08-04 --profile minimal --component rust-src
cargo build --release --locked --manifest-path rust-crates/libraries/zkvm/methods/pico/Cargo.toml
```

Output: `rust-crates/libraries/zkvm/artifacts/v2.0/pico.elf` (not tracked by Git).
No `cargo-pico` installation or separate Pico Rust compiler is needed.

## Lockfile maintenance

The ECDSA crypto patch has an **unversioned** Git dependency on
`pico-patch-libs`. Resolving it afresh pulled v2.1.2 and failed to compile against
the v1 crypto patch (`Secp256k1Point::unwrap` no longer exists). The checked-in
guest lockfile pins that dependency to v1.1.6's commit
`5aa0bd9ca60c366618856681d8a7ad356753a979`, matching the SDK/VM. Two source IDs
(tagged and untagged Git URLs) are expected, both at this same commit.

Do not casually regenerate this lockfile. If it must be regenerated, restore the
untagged dependency's precise revision before building:

```sh
cargo +nightly-2025-08-04 update \
  --manifest-path rust-crates/libraries/zkvm/methods/pico/program/Cargo.toml \
  -p 'git+https://github.com/brevis-network/pico.git#pico-patch-libs' \
  --precise 5aa0bd9ca60c366618856681d8a7ad356753a979
```

Review every resulting dependency change. Do not replace SDK/circuit versions
or remove the crypto patches merely to resolve a compiler error.

## Local execution check

The host SDK also requires a nightly compiler. Given an input encoded by
`dcap_rs::v2::encode_guest_input_v2` (signed quote, complete collateral and an
explicit verification timestamp):

```sh
cargo +nightly-2025-08-04 run --locked \
  --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features pico --example pico_v2_execute \
  --target-dir rust-crates/target -- \
  rust-crates/libraries/zkvm/artifacts/v2.0/pico.elf /path/to/v2-input.bin
```

This prints the native verifying-key identifier and executes the guest using
Pico v1.1.6/KoalaBear, comparing the complete journal to native V2 verification
at the same input timestamp. It does not use `DEV_MODE`, an old ELF or a cached
`proof.data`, and does not generate a proof or register a program ID.

Build-driver tests can run without compiling the guest:

```sh
rustc --edition 2021 --test rust-crates/libraries/zkvm/methods/pico/build_support.rs -o /tmp/dcap-pico-build-tests
/tmp/dcap-pico-build-tests
```

## Release gate

Compiler compatibility and execution parity do **not** prove compatibility with
the deployed universal verifier. Independently reproducible builds and a real
proof verified by the existing contract remain mandatory. Supply its matching
`vm_pk`, `vm_vk` and `constraints.json` for EVM proving; do not generate a new
trusted setup as a substitute for those artifacts.
