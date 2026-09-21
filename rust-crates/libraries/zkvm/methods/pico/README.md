# Pico V2 guest build

This driver retains Pico SDK/VM **v1.1.6**, KoalaBear and its existing proof
system. It does not use `cargo-pico`: that release hardcodes nightly-2024-11-27
and does not pass `--locked` to its inner Cargo build.

Support scope, confirmed 2026-09-11: **local validation only**. This release
does not deploy/enable Pico on any network or add Pico V2 IDs/defaults/routes.
Keep the existing network support matrix and local Pico SDK support unchanged.

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

## Reproducible local-validation build

Use the repository's frozen Pico image with nightly-2025-08-04 and rust-src
already installed, and compare two clean containers using the **same image ID
and platform**. Do not mount a host compiler or require host/Docker equality.
See the [paired Docker build procedure](../../../../../docs/dcap-v2-container-rebuild.md).
The local commands below remain useful for development/execution checks.

## Local install and build

From the repository root:

```sh
rustup toolchain install nightly-2025-08-04 --profile minimal --component rust-src
cargo build --release --locked --manifest-path rust-crates/libraries/zkvm/methods/pico/Cargo.toml
```

Output: `rust-crates/libraries/zkvm/artifacts/v2.0/pico-strict.elf` (not tracked by Git).
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

The checked-in [V3/V4/V5 fixtures](../../../../../evm/forge-test/assets/v2/fixtures/README.md)
include an offline export command; no prior local diagnostic files are needed.

```sh
cargo +nightly-2025-08-04 run --locked \
  --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features pico --example pico_v2_execute \
  --target-dir rust-crates/target -- \
  rust-crates/libraries/zkvm/artifacts/v2.0/pico-strict.elf /path/to/v2-input.bin
```

This prints the native verifying-key identifier and executes the guest using
Pico v1.1.6/KoalaBear, comparing the complete journal to native V2 verification
at the same input timestamp. It does not use `DEV_MODE`, an old ELF or a cached
`proof.data`, and does not generate a proof or register a program ID.

`--expect-reject` covers the mode-divergent Alibaba V5 policy fixture
(non-zero `MR_SERVICE_TD`): native verification in the selected mode must
reject the input, and the emulator's non-zero guest halt (surfaced by the SDK
as a host panic) counts as the guest rejection. Faults, cycle limits and
transport errors are not validation rejections. The strict program must reject
while the minimal program accepts the same exported input with journal parity.

Build-driver tests can run without compiling the guest:

```sh
rustc --edition 2021 --test rust-crates/libraries/zkvm/methods/pico/build_support.rs -o /tmp/dcap-pico-build-tests
/tmp/dcap-pico-build-tests
```

## Local validation status (not a production release gate)

- [x] Two clean fixed-image builds at source `81646e5` match in bytes and native ID.
- [x] Both programs execute the authentic Google V5 fixture with exact native
  journal parity; build-driver and local SDK regression results are recorded in
  the [progress log](../../../../../docs/dcap-v2-progress.md).
- [ ] Local real-proof generation and verification with a matching local
  verifier remain untested. Execution parity is not proof verification. Track
  this work separately; it does not block RISC Zero/SP1 production rollout.

Local EVM proof tests need a matching circuit, `vm_pk`, `vm_vk` and verifier.
For a deliberately fresh local test setup, use a separate test-only directory
and its newly generated matching verifier; do not claim compatibility with the
repository's old verifier or deploy it to supported networks. If testing a
specific pre-existing verifier instead, recover and authenticate its matching
parameters using the conditional procedure below. No setup was generated by
this documentation change. Retain the current SDK/circuit family.

## Optional compatibility with an existing verifier

This procedure applies only when an explicitly selected existing verifier is
the local test target. It is **not** a prerequisite for production release and
does not establish that a Pico verifier is deployed on a supported network.
Ask that verifier's setup operator or CI artifact owner
for the **original Pico 1.1.6 / KoalaBear setup bundle**:

- `vm_pk` and `vm_vk`, plus their authenticated release SHA-256 manifest;
- the corresponding `constraints.json` and/or compiled `vm_ccs`, circuit/SDK
  revision and the exact gnark prover image digest;
- generated `Groth16Verifier.sol`, target-chain deployment address and bytecode
  hash, so the bundle can be matched to the intended existing verifier.

These are public proving/verifying parameters, **not private keys or setup
secrets**. Do not request or distribute toxic waste. A proving key cannot be
reconstructed from an on-chain verification key.

Correction to the earlier checklist: the pinned SDK's `write_onchain_data`
generates `constraints.json` and the witness during proving. Its gnark CLI
compiles that circuit and reads `vm_pk`/`vm_vk`. Therefore a missing original
`constraints.json` is not automatically irrecoverable, but the regenerated
circuit still has to match the original setup. `vm_ccs` is also distributed by
upstream's separate performance/server tooling; it is not a replacement for the
JSON required by this SDK's CLI path.

When reusing an existing verifier, do not start this repository's Pico prover
with an empty artifacts directory:
the current host sets `need_setup = !vm_pk.exists()`, and upstream then invokes
`setup`. Stage and verify the correct bundle first, and use its directory as
`PicoConfig.artifacts_path` / the CLI's `--artifacts-path`. Preserve original
parameters separately from writable per-proof witness/output files.

### Public download candidate checked on 2026-09-11

The pinned upstream
[download helper](https://github.com/brevis-network/pico/blob/5aa0bd9ca60c366618856681d8a7ad356753a979/perf/src/common/gnark_utils.rs)
lists `vm_pk`, `vm_vk` and `vm_ccs` at the unversioned
`picobench.s3.us-west-2.amazonaws.com/koalabear_gnark/` location. Version names
alone do not authenticate these mutable objects.

The 520-byte public `vm_vk` downloaded from that location has SHA-256
`8780b43ab8b9177d0ff7b289b68efd2cd25fde153d189d2b67401d4b49d5e774`.
Decoded using the pinned gnark key field order and BN254 subgroup-checking
decoder, its alpha, negated beta/gamma/delta and three public-input points
**do not match any of the 20 corresponding coordinate constants** in this
repository's `evm/contracts/zk/pico/Groth16Verifier.sol` at `81646e5`.
For example, its alpha X is
`2387709920592184083440184305498248923596928447823501187834217907152206095815`,
whereas the contract's alpha X is
`13491508310322644295278574150660374920811253940772186555574957977326729177946`.
This candidate is rejected; the large proving key was not downloaded and no
setup was run. A specific deployed chain/address was not inventoried in this
check; the mismatch is not evidence of an existing supported Pico deployment
and is no longer an online release blocker.

If the original bundle cannot be recovered, a new local setup means a **new
matching local verifier**, not compatibility with the old one. Any future
network deployment requires a separate scope/security/deployment decision;
this release explicitly excludes it.
