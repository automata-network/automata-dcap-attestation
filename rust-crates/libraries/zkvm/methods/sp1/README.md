# SP1 V2 guest build and local execution

Use the V5 family: CLI/build driver 5.2.2, the host workspace's locked SDK 5.2.2,
and guest `sp1-zkvm = 5.2.1`. Do not run an unversioned `sp1up` or migrate to V6
to address a local build error. The guest and driver lockfiles can contain
compatible transitive 5.2.4 crates; they do not replace the host SDK lockfile.

## Toolchain

```sh
sp1up --version v5.2.2
rustup toolchain install 1.88.0 --profile minimal --no-self-update
rustc +succinct --version
cargo +1.88.0 --version
```

Expected compiler: `rustc 1.88.0-dev`, from the official
`succinct-1.88.0` distribution, with the
`riscv32im-succinct-zkvm-elf` standard library. Linux ARM64 is supported.

The Succinct distribution does **not** include Cargo. `cargo +succinct` falls
back to the system Cargo. This is not a sufficient readiness check: Cargo
1.97.1 passes `--remap-path-scope`, which Rust 1.88 does not accept. The driver
therefore pins Cargo 1.88 for its child processes and checks its version before
building. `sp1-build` still explicitly selects the Succinct **rustc**, sysroot,
RISC-V target and codegen flags. The default system toolchain is not changed.

The guest lockfile pins `ruint` to 1.17.0, matching the host workspace; 1.20.0
requires Rust 1.90 and cannot be built by succinct-1.88.0. Preserve this pin when
updating the guest lockfile. The actual guest Cargo build uses `--locked`.

## Canonical release build

Use the official `ghcr.io/succinctlabs/sp1:v5.2.2` image, pinned by digest and
`linux/amd64`, and compare two clean Docker builds. Equality with a native host
build is not required. See the [paired Docker build procedure](../../../../../docs/dcap-v2-container-rebuild.md).
The local command below is for development/execution checks, not the canonical
release artifact source.

## Local build

From the repository root:

```sh
CARGO_BUILD_JOBS=2 cargo build --release --locked \
  --manifest-path rust-crates/libraries/zkvm/methods/sp1/Cargo.toml \
  --target-dir rust-crates/target
```

The target directory must be named `target` for the upstream SP1 host build
scripts. The candidate ELF is written to
`rust-crates/libraries/zkvm/artifacts/v2.0/sp1.elf`. Old embedded ELFs and
deployment configuration are not modified.

Initial builds need network access to fetch the official V5 verifying-key map
even if Cargo dependencies have been cached. Upstream verifies its SHA-256:
`5e735f6e44f56e9eee91e5626252663afcc5263287d1c5980367b3f9f930a0e8`.
Do not substitute a dummy map, disable VK verification or set `DOCS_RS` to
bypass this dependency.

## Execute a real input

Use an ABI input produced by `dcap_rs::v2::encode_guest_input_v2`, with the signed
quote, full collateral and a fixed verification timestamp:

The checked-in [V3/V4/V5 fixtures](../../../../../evm/forge-test/assets/v2/fixtures/README.md)
include an offline export command; no prior local diagnostic files are needed.

```sh
CARGO_BUILD_JOBS=2 cargo run --locked \
  --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features sp1 --example sp1_v2_execute \
  --target-dir rust-crates/target -- \
  rust-crates/libraries/zkvm/artifacts/v2.0/sp1.elf /path/to/v2-input.bin --negative
```

The example explicitly uses the local CPU client without prebuilding the unused
recursive-program cache (VK checks and default circuit shapes stay enabled),
prints the native program ID and circuit version, and compares the journal against native V2
verification. `--negative` additionally checks that native and guest both reject
eight cases: changed signed body/signature, trailing zeros, truncation,
unsupported quote version, oversized signature length, and pre-/post-validity
timestamps. Rejection must be a guest validation panic (exit code 1), not an
unsupported syscall or the local 500-million-cycle execution limit.
It does not select a network prover, send a paid proving request,
generate a proof, or register any program ID.

### Low-memory host linking

If GNU `ld` is killed while linking the host example, use the Rust toolchain's
bundled LLD with limited threads. These flags apply only to the final host
example, not dependencies or the guest ELF. Run the resulting binary directly
so that `cargo run` does not relink it with the default linker:

```sh
SP1_HOST_SYSROOT="$(rustc --print sysroot)"
SP1_HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
CARGO_BUILD_JOBS=1 cargo rustc --locked \
  --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features sp1 --example sp1_v2_execute \
  --target-dir rust-crates/target -- \
  -C "link-arg=-B${SP1_HOST_SYSROOT}/lib/rustlib/${SP1_HOST_TRIPLE}/bin/gcc-ld" \
  -C link-arg=-fuse-ld=lld -C link-arg=-Wl,--threads=2
rust-crates/target/debug/examples/sp1_v2_execute \
  rust-crates/libraries/zkvm/artifacts/v2.0/sp1.elf /path/to/v2-input.bin --negative
```

This fallback was tested on Linux ARM64; it does not alter the default toolchain
or require a system-wide linker change.

Execution parity does not establish real-proof/universal-verifier compatibility.
Independent reproducibility and real proof checks remain release prerequisites;
see the [progress evidence](../../../../../docs/dcap-v2-progress.md).

## Local real-proof diagnostic

The separate `sp1_v2_prove_local` example explicitly selects the local CPU
prover and a **core** proof. It never chooses the network prover or mock mode.
Use the canonical Docker ELF:

```sh
CARGO_BUILD_JOBS=2 cargo run --release --locked \
  --manifest-path rust-crates/Cargo.toml -p automata-dcap-zkvm \
  --features sp1 --example sp1_v2_prove_local --target-dir rust-crates/target -- \
  /path/to/canonical/sp1.elf /path/to/v2-input.bin /path/to/new.proof
```

Use the optimized **host** build for real proving; this does not rebuild or
change the supplied canonical guest ELF. `RUST_LOG=info` enables SDK progress
logs. An unoptimized dev host can add substantial proving overhead even when
guest execution already passes. For the low-memory linking fallback, include
`--release` and run `target/release/examples/sp1_v2_prove_local` afterwards.

The runner verifies the proof against the ELF-derived key, compares the entire
journal with native V2, and rejects a changed journal, wrong verifying key and
changed proof commitment.
It writes only after those checks, refusing to overwrite an existing file.
Append `--verify` to recheck an existing proof without proving again. Default
VK checks and circuit shapes remain enabled; only the unused recursive cache
is disabled. `FRI_QUERIES` must be unset or the SDK's default `100`; weakened
query counts are refused. No guest source or release program ID is changed.

The runner uses 2^18-cycle shards, a batch size of one, and a 500-million-cycle
limit. Optional upstream pipeline settings `TRACE_GEN_WORKERS=1`,
`CHECKPOINTS_CHANNEL_CAPACITY=1` and `RECORDS_AND_TRACES_CHANNEL_CAPACITY=1`
limit concurrent buffers, not cryptographic checks. Set memory/wall-clock
limits outside the runner. On the tested Linux/glibc ARM64 worker,
`MALLOC_ARENA_MAX=2 RAYON_NUM_THREADS=4` plus those single-buffer settings
completed the SGX diagnostic in 11:55 with about 7.17 GiB peak RSS. The earlier
attempt failed allocation under a 10 GiB **virtual address-space** limit; the
successful retry allowed 24 GiB virtual space and watched actual RSS/system
available memory separately. This is not a guarantee that every input fits
8 GiB RAM; leave system headroom and monitor actual memory pressure. Allocator
and host optimization settings do not weaken FRI/VK checks or change the guest.
Use the low-memory linking recipe above with this
example name if needed. A core proof is not an EVM Groth16/Plonk proof;
compression and actual universal-verifier/FeeV2 acceptance remain required.
See the [public-quote validation record](../../../../../docs/dcap-v2-public-quotes-validation.md)
for actual outcomes; a compiled runner or timed-out attempt is not proof success.
