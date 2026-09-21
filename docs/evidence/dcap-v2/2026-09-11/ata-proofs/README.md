# Extended serial local-proof record — 2026-09-11

## Repository contents and optional local archives

Only this verification record and the small checksum manifests are intended
for Git. Complete proofs, logs and `.tar.gz` archives are kept locally and
ignored, not deleted. A fresh checkout does **not** contain those archives.
The checked-in runners, signed fixture and [repeatable procedure below](#repeat-without-the-archives)
are sufficient to repeat the test after obtaining the pinned toolchains and
canonical Docker programs. They do not require this worker's `/tmp` files.

The result summary is a historical test record, not independently inspectable
proof evidence by itself. To audit the exact previous run without reproving,
obtain its optional archives separately and verify their recorded hashes.
No external archive service or upload is configured by this change.

This is separate from the earlier execution-only and 600-second timeout
evidence in `../ata-quotes`. No old evidence has been replaced. See the
[validation report](../../../../dcap-v2-public-quotes-validation.md#extended-serial-retry-2026-09-11)
for scope, timing and actual verification results.

The optional local `risc0-sgx-composite.tar.gz` contains the real composite receipt, complete
proving/negative-test log, elapsed/resource measurements, start/end records,
exit code and artifact/runner preflight hashes. The receipt was written only
after successful cryptographic verification, full journal equality and three
rejection checks (modified journal, wrong image ID, modified seal).

Receipt SHA-256:
`e360696731f61e585a9cfb63cc6c64e4e853c04092c239ab1fddd0d0153d5c5f`.
It binds the canonical Docker image ID
`0x9d4a47be495ab06a6a84b24d856a13a68312d8fdea487bcb8aa6931a322f9b9b`
and the ATA SGX fixture's fixed 833-byte OutputV2 2.1 journal.

`sp1-sgx-core.tar.gz` contains the real local CPU core proof, full proving and
negative-test log, timings, exit code, hashes, and the memory-tuned run script
and watcher log. It completed in 11:55.22 with 7,518,080 KiB maximum RSS.
Before saving, the runner checked cryptographic verification, exact journal
equality, and rejection of a modified journal, wrong verifying key and
modified proof commitment. Its native program ID is
`0x000544ec0a86e3860bac6c329267c270beed1f7be600519128022a02f4b9f170`.
The saved proof SHA-256 is
`3b601fb250ecbc739f03a79a03eee8979cc2d541d8b61e6582077aa4101db721`.
The raw proof is 115,484,043 bytes; its archive is 94,689,156 bytes. These are
core-proof sizes, not EVM calldata sizes or estimates of on-chain gas.

`host-runs-and-readback.tar.gz` contains:

- `dcap-proof-hourly.LOwQLe/`: deliberately interrupted one-hour wrapper.
- Selected `dcap-proof-serial.vQ3WrM/` files: serial run controls/resource log,
  interrupted SP1 dev-host attempt, and initial release-build HTTP 400 log.
- `dcap-sp1-release-proof.fJRbnY/`: successful host build/guard checks and the
  release proof attempt that failed allocation under a 10 GiB virtual limit.
  Its authoritative wrapper exit code is 134; GNU time's signal-termination
  output includes an `Exit status: 0` line that is **not** a successful run.
- `dcap-proof-readback.5MyhZn/`: scripts and logs for fresh processes loading
  receipts/proofs extracted from the two archives. Both passed cryptographic
  verification, full journal equality and all three rejection checks again:
  RISC Zero 1:05.80, SP1 0:13.85, both exit 0. These are read-back verification
  times, not a second proof generation or independent prover implementation.
- The exact current Rust diagnostic runner sources. No target cache or
  duplicate 115 MB proof is included in this controls/read-back archive.

All prover runs were serial; the read-back run started after SP1 proving
finished. No prover or watcher remains running. The successful artifacts use
the original ATA SGX V3 fixture only, not the TDX/V5 fixtures. Input SHA-256:
`d0ba508f6946915279d1662516b0324a1e899c073ca94e0e13b69407287aec94`;
journal SHA-256:
`63a380dbab7865ccc903c7c87bd50b187d44022e97affd9a7d63072ebd07dba9`.

Only if the optional archives are present, verify their hashes from this
directory with `sha256sum --check SHA256SUMS`. Missing archives in a fresh
checkout are expected, not evidence of failed cryptographic verification.
For fresh local receipt verification, extract to a new directory and pass the
canonical Docker program, offline-exported ATA SGX input and receipt to
`risc0_v2_prove_local PROGRAM INPUT RECEIPT --verify`. That re-runs the positive
and negative checks without generating another proof.
For SP1 use `sp1_v2_prove_local PROGRAM INPUT PROOF --verify` with the optimized
host, canonical Docker ELF and the same SGX ABI input. Relative archive entries
can be extracted into a new empty directory; paths in historical run scripts
refer to this worker's temporary folders and must be adapted on another worker.

`SOURCE_SHA256SUMS` records the current proof runners, host Cargo manifest/lock,
SGX fixture and guest locks. Check it **from the repository root**:

```sh
sha256sum --check docs/evidence/dcap-v2/2026-09-11/ata-proofs/SOURCE_SHA256SUMS
```

The SP1 runner hash intentionally differs from the earlier execution-only
source manifest: logging, a default `FRI_QUERIES=100` guard and proof-commitment
rejection were added before the successful release-host run. Old evidence
manifests are historical snapshots, not rewritten to conceal later changes.
Guest source remains `81646e5754a8124d4a70a483882f11b515c98c7b`;
guest bytes/native IDs and all SDK/lock versions remain unchanged.

The receipt/core proof are **not** EVM Groth16/Plonk proofs. No remote proving, setup, network
registration or live deployment was performed. Pico remains local-only and
was not part of this extended RISC Zero/SP1 retry.

## Repeat without the archives

1. Obtain or build the pinned canonical programs using the
   [paired Docker procedure](../../../../dcap-v2-container-rebuild.md).
   Preserve the recorded guest source, Docker digests, program bytes and
   native IDs; do not substitute the legacy embedded guest or a host rebuild.
2. Install the [RISC Zero](../../../../../rust-crates/libraries/zkvm/methods/risc0/README.md)
   and [SP1](../../../../../rust-crates/libraries/zkvm/methods/sp1/README.md)
   prerequisites. RISC Zero proving needs local `r0vm` 3.0.3 and loopback IPC.
   Dependencies must be available before using Cargo's optional `--offline`.
3. From the repository root, adapt only the two program paths below and run
   in Bash on a worker with sufficient memory. The tested worker had about
   15.6 GiB RAM; monitor physical memory and leave system headroom. These
   commands do not install a watchdog or impose a one-hour timeout. For
   low-memory linking use the documented LLD fallback and run that binary
   directly rather than relinking it through `cargo run`.

```bash
(
set -euo pipefail
DCAP_R0_PROGRAM=/absolute/path/to/canonical/risc0.elf
DCAP_SP1_PROGRAM=/absolute/path/to/canonical/sp1.elf
DCAP_PROOF_RUN="$(mktemp -d /tmp/dcap-ata-proof-repeat.XXXXXX)"
printf 'Results directory: %s\n' "$DCAP_PROOF_RUN"

sha256sum --check docs/evidence/dcap-v2/2026-09-11/ata-proofs/SOURCE_SHA256SUMS
printf '%s  %s\n' \
  0560682c1b2edee108406f66cd3d174671941da2267846ebd076e6b335762371 "$DCAP_R0_PROGRAM" \
  95f7c4bd575fe4bbe9bcb55538941213c5c7cf49bd929dde811b9fb85ad2f69f "$DCAP_SP1_PROGRAM" \
  | sha256sum --check -

CARGO_BUILD_JOBS=2 cargo run --locked --manifest-path rust-crates/Cargo.toml \
  -p dcap-rs --example v2_fixture --target-dir rust-crates/target -- \
  export evm/forge-test/assets/v2/fixtures/ata-sgx-v3.json "$DCAP_PROOF_RUN/input.bin"
printf '%s  %s\n' \
  d0ba508f6946915279d1662516b0324a1e899c073ca94e0e13b69407287aec94 "$DCAP_PROOF_RUN/input.bin" \
  | sha256sum --check -

unset DEV_MODE RISC0_DEV_MODE
export VERIFY_VK=true FIX_CORE_SHAPES=true FIX_RECURSION_SHAPES=true FRI_QUERIES=100
export RAYON_NUM_THREADS=4 MALLOC_ARENA_MAX=2 RUST_LOG=info
export TRACE_GEN_WORKERS=1 CHECKPOINTS_CHANNEL_CAPACITY=1 RECORDS_AND_TRACES_CHANNEL_CAPACITY=1

for backend in risc0 sp1; do
  program="$DCAP_R0_PROGRAM"
  output="$DCAP_PROOF_RUN/risc0.receipt"
  if [[ $backend == sp1 ]]; then
    program="$DCAP_SP1_PROGRAM"
    output="$DCAP_PROOF_RUN/sp1.proof"
  fi
  CARGO_BUILD_JOBS=2 cargo build --release --locked \
    --manifest-path rust-crates/Cargo.toml -p automata-dcap-zkvm \
    --features "$backend" --example "${backend}_v2_prove_local" --target-dir rust-crates/target
  runner="rust-crates/target/release/examples/${backend}_v2_prove_local"
  "$runner" "$program" "$DCAP_PROOF_RUN/input.bin" "$output" \
    2>&1 | tee "$DCAP_PROOF_RUN/${backend}-prove.log"
  "$runner" "$program" "$DCAP_PROOF_RUN/input.bin" "$output" --verify \
    2>&1 | tee "$DCAP_PROOF_RUN/${backend}-readback.log"
  sha256sum "$output"
done
)
```

Each invocation must exit 0, report the expected native program ID, pass full
833-byte journal equality, and print the positive and all three rejection
checks as `PASS`. The proof-generation runner saves only after these checks;
`--verify` reloads that saved file in a fresh process. `pipefail` prevents a
successful log writer from hiding a failing prover. The backends run serially.
Proof SHA-256 values above identify the **historical artifacts**: newly
generated proof bytes need not match them. Verify the new proof cryptographically
and compare the program, input and journal, not just a proof-file digest.

For raw Rust/Solidity/Go and execution-only SGX/TDX checks, use the
[public-quote regression commands](../../../../dcap-v2-public-quotes-validation.md#repeatable-commands-and-fork-handoff).
The original padded TDX remains a negative case; the exact extracted prefix
is the positive case. This procedure still does not exercise EVM compression,
universal verifiers, FeeV2 proof acceptance or forked networks.
