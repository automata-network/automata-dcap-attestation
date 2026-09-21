# Fork-only acceptance runners

> Compact revision: the historical inline-body/SP1 v5 six-cell result below is
> not current acceptance. `DcapV2ForkTest` now uses compact fixtures, rejects old
> selectors and requires explicit `DCAP_RISC0_STRICT_ID` / `DCAP_SP1_STRICT_ID`
> for new real proofs. Optional `DCAP_*_V2_VERIFIER` selects a reviewed verifier
> (SP1 v6 compatibility must be verified). The older standalone Anvil/gas/replay
> orchestration still needs migration; do not run it as compact acceptance.
> See [current revision status](../../docs/dcap-v2-revision-progress.md).

Run from the repository root unless stated otherwise. These are acceptance
tools, not production deployment scripts. No operator key, broadcast to public
RPC, remote proving service or new trusted setup is used. The scoped six-cell V2
Sepolia run is [complete](../../docs/dcap-v2-sepolia-acceptance.md); broader release
gates remain explicit in the [checklist](../../docs/dcap-v2-fork-validation.md).
Record fresh output paths; do not overwrite previous evidence. Large proofs,
circuits and logs belong in ignored local directories or external storage.

**September 14 scope:** use the existing pinned Ethereum Sepolia fork for the
complete deployment/upsert/raw/ZK/SDK/negative/rollback/gas workflow. RISC Zero
TDX V4 uses `ata-tdx-v4.json`; RISC Zero/SP1 V5 use the existing Google `v5.json`.
Other-network recipes/results are supplementary, not a requirement to repeat
full E2E on every registry chain. Actual selected rollout targets still need
separate read-only configuration preflight. The previously requested historical
Story CRL regression remains a focused follow-up, not a full-chain E2E expansion.

## Read-only discovery

```bash
DCAP_RUN=$(mktemp -d /tmp/dcap-fork.XXXXXX)
node scripts/fork-dcap-v2/inventory.mjs "$DCAP_RUN/inventory.json"
```

For a pinned chain, `state-inventory.mjs CHAIN PUBLIC_RPC BLOCK NEW_REPORT.json`
reads observed code hashes, dependencies, owners, defaults and Fee/Router history.
`event-inventory.mjs` provides bounded pagination when a provider requires it.
Only after a complete range was returned, replay and compare the available
public mappings, then inventory SP1 gateway selectors separately:

```bash
node scripts/fork-dcap-v2/replay-events.mjs "$DCAP_RUN/state.json" "$DCAP_RUN/replayed.json"
node scripts/fork-dcap-v2/sp1-routes.mjs "$DCAP_RUN/state.json" "$DCAP_RUN/sp1-routes.json"
node scripts/fork-dcap-v2/risc0-routes.mjs "$DCAP_RUN/state.json" "$DCAP_RUN/risc0-catalog.json"
```

Do not infer unlogged initial caller/configuration state from missing events.
RISC Zero router add/remove operations in the vendored implementation do not
emit selector events, so an event query cannot enumerate that mapping. Reuse
preserves the existing router, but full historical discovery requires deployment/
transaction records. A known active selector readback is not a complete inventory.
The RISC Zero runner reads all 12 Sepolia candidates in the vendored upstream
catalog, including removed and paused entries. It explicitly does not claim
exhaustiveness for administrator transactions outside that catalog.

An optional list of chain IDs limits reads. This collects defaults, not complete
non-enumerable route history. Never equate a failed RPC or unsupported enum ABI
with an absent deployment. Confirm chain IDs and record block hashes, not only
block numbers. Retired/unreachable chains require an explicit scope decision.

`state-inventory.mjs CHAIN PUBLIC_RPC PINNED_BLOCK NEW_REPORT.json` additionally
collects code hashes/owners, evaluation 17–21 DAO/resolver addresses and
genesis-to-pin Fee/Router configuration events. Missing RPC/history fields stay
explicitly partial; this is source material, not a completed release manifest.

## Signed collateral and raw fork tests

The checked-in JSON fixtures contain signed collateral and frozen journals.
Existing DAOs may use async upsert protocol 2. Generate separate upload plans
for the three FMSPC/TEE pairs using the exact reviewed QPL encoder (no QPL changes):

```bash
mkdir -p evm/forge-test/assets/v2/local-fork
node scripts/fork-dcap-v2/prepare-async-tcb.mjs ../automata-dcap-qpl \
  evm/forge-test/assets/v2/fixtures/ata-sgx-v3.json \
  evm/forge-test/assets/v2/local-fork/00606a000000-0.json
node scripts/fork-dcap-v2/prepare-async-tcb.mjs ../automata-dcap-qpl \
  evm/forge-test/assets/v2/fixtures/ata-tdx-v4.json \
  evm/forge-test/assets/v2/local-fork/00806f050000-1.json
node scripts/fork-dcap-v2/prepare-async-tcb.mjs ../automata-dcap-qpl \
  evm/forge-test/assets/v2/fixtures/v5.json \
  evm/forge-test/assets/v2/local-fork/90c06f000000-1.json
```

The encoder source hash is checked; cached Rust dependencies are required.
Run inside `evm/`:

```bash
FOUNDRY_PROFILE=fork_osaka \
DCAP_FORK_RPC=https://rpc.sepolia.ethpandaops.io \
DCAP_FORK_CHAIN=11155111 DCAP_FORK_BLOCK=11689923 DCAP_FORK_EVM=osaka \
DCAP_FORK_ASYNC_DIR=forge-test/assets/v2/local-fork \
forge test --evm-version osaka --match-contract '^DcapV2ForkTest$' -vv
```

This profile executes Osaka's real P-256 precompile and compiles release
bytecode for Paris. Do not silently use Osaka for networks whose actual execution
rules differ. Do not replace real cryptography with mocks to get a passing test.
Hoodi/mainnet pins and results are recorded in the execution record.
Public RPCs may prune these pins; use archive access or record a new pin and
revalidate collateral. Never warp time independently of stored collateral to
hide expiry/rollback failures. Story CRL tests have a separate historical-window
requirement documented in the execution record.
Matching a collateral body hash alone does not establish validity: signed
renewals can retain that hash while changing the validity interval. The harness
checks both and uses a real signed upsert where necessary. The transaction runner
also renews signed QE/evaluation data when required, with an explicit DAO owner
grant of `ATTESTER_ROLE`. Owner status alone is not sufficient for those upserts.
It must not be generalized to another chain by just replacing its RPC.

## Local transactions, SDK and gas

Start a fresh process on loopback only (a second terminal), then leave it running:

```bash
anvil --host 127.0.0.1 --port 18545 \
  --fork-url https://rpc.sepolia.ethpandaops.io \
  --fork-block-number 11689923 --chain-id 11155111 --hardfork osaka
```

The default deployment runner requires a fresh, exact Ethereum Sepolia fork and
Paris artifacts from the profile above. It impersonates accounts only on this
local node and records real transaction receipts; V2 ZK remains paused.

```bash
node scripts/fork-dcap-v2/anvil-deploy.mjs \
  http://127.0.0.1:18545 "$DCAP_RUN/deployment.json"
```

Inside `go-sdk/`:

```bash
DCAP_ANVIL_REPORT="$DCAP_RUN/deployment.json" \
DCAP_SDK_GAS_REPORT="$DCAP_RUN/go-raw.json" \
go test ./packages/godcap/attestationv2 -run TestForkRawV2 -count=1 -v
```

Back at the root, Rust/native parity (do not run concurrently with fork writes):

```bash
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-verifier --example fork_v2_sdk -- \
  "$DCAP_RUN/deployment.json" evm/forge-test/assets/v2/fixtures "$DCAP_RUN/rust-raw.json"
node scripts/fork-dcap-v2/gas-report.mjs \
  "$DCAP_RUN/deployment.json" "$DCAP_RUN/go-raw.json" "$DCAP_RUN/rust-raw.json" "$DCAP_RUN/gas.json"
```

The gas report reconciles exclusive call-tree residuals to receipts, without
double-counting child gas. Root residual includes transaction accounting; it is
not an isolated intrinsic-gas measurement. Standard intrinsic components and the
data floor are reported separately, not added again to call-tree buckets. Net
gas above intrinsic still includes refund/floor effects. No L2 data fees or market-price claims
are inferred. The runner accepts only the two reviewed profiles below; additional
chains need their own reviewed manifest, pin and execution rules.

The explicit `op-sepolia-karst` raw profile was exercised at block
48718178 / chain 11155420. It requires Anvil 1.8.1 with `--optimism --hardfork karst`
and checks the exact block hash/network runtime. It refuses unexpected active
backends instead of enabling ZK. Do not repoint the default profile at an L2 RPC.
The execution record pins the official ARM64 tool archive/binary hashes; install
that test runtime into an isolated directory, not over the existing build tools.

```bash
"$DCAP_KARST_ANVIL" --host 127.0.0.1 --port 18547 --optimism --hardfork karst \
  --fork-url https://sepolia.optimism.io --fork-block-number 48718178 --chain-id 11155420
# In a separate terminal, after signed collateral preparation:
node scripts/fork-dcap-v2/anvil-deploy.mjs \
  http://127.0.0.1:18547 "$DCAP_RUN/op-deployment.json" op-sepolia-karst
```

If the evaluation-number cache is expired, the runner requires public Intel
`sgx-tcbeval.json` / `tdx-tcbeval.json` under `assets/v2/local-fork/`. Obtain these
from the corresponding PCS v4 `/tcbevaluationdatanumbers` endpoints and preserve
the signatures. The actual DAO must accept the signed upsert; changing the clock
or manufacturing an evaluation record is not an alternative. Match capture
validity to the fork pin. The same SDK raw commands use the new deployment report;
only the two explicit reviewed origins are accepted, not arbitrary chains.
The completed OP replay includes 48 bootstrap and 12 Go/Rust raw transactions.
Its receipts omit L1/operator fees; the gas report preserves any such fields if
present but never infers that missing fields mean zero. This is not yet complete
OP rollout/rollback or total user-fee acceptance.

For negative transaction gas, use an exclusively owned local Anvil instance
with no concurrent writers. This records positive controls and rejection
receipts/traces, then restores its exact initial snapshot (including the test's
temporary pause/freeze). It removes only the temporary test transactions from
the local chain; their measured evidence remains in the output file:

```bash
node scripts/fork-dcap-v2/negative-gas.mjs \
  "$DCAP_RUN/deployment.json" evm/forge-test/assets/v2/fixtures/ata-sgx-v3.json \
  "$DCAP_VERIFIED_EVM_PROOF" "$DCAP_RUN/negative-gas.json"
```

Returned `false` and transaction reverts are distinct outcomes. The script checks
both and forbids accepted events on negatives. Gas is cap-dependent for invalid
precompile inputs; no worst-case bound is implied. Local snapshot restoration
must not be confused with reversing a production route freeze.

### SDK collateral acquisition and input parity

Run after deployment, with no concurrent writers to the local fork. The Go V2
API is additive: `NewCollateralV2FromQuoteParser` selects PCS API v4 / TCB Info
v3 independently of quote version and pins one evaluation for both documents;
`GenerateInputV2` emits the ABI envelope with an explicit verification timestamp.
The old Go input/proving-service APIs retain their old format and program IDs.
These commands do not contact a paid or remote prover:

```bash
DCAP_ANVIL_REPORT="$DCAP_RUN/deployment.json" \
DCAP_COLLATERAL_GO_OUT="$DCAP_RUN/go-inputs" \
go test ./go-sdk/packages/godcap/attestationv2 -run '^TestForkV2CollateralAcquisition$' -count=1 -v
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --example fork_v2_collateral -- \
  "$DCAP_RUN/deployment.json" evm/forge-test/assets/v2/fixtures \
  "$DCAP_RUN/cross-sdk-inputs" "$DCAP_RUN/go-inputs"
```

The Rust runner authenticates every generated input with native V2 verification
and compares full journals, for all three fixtures, explicit/default evaluations
and direct/Multicall3-with-fallback reads. Go acquisition alone is not proof or
native-verification success. Both SDKs produce byte-identical acquired inputs.
At this pin, some on-chain JSON documents have older still-valid issue/expiry
dates and signatures than frozen fixtures; semantic collateral hashes/journals
remain equal. Do not overwrite frozen proof inputs or claim identical collateral
documents merely because their semantic hashes match. Acquisition checks current
host-time expiry; a later rerun can legitimately require renewed signed collateral.

If the historical RPC is pruned, use an archive endpoint at the same pin. A fresh
Anvil instance may be needed: on September 14 changing the old node's URL did not
clear its cached historical read errors. Do not inject fabricated storage or
change the pinned timestamp to make acquisition pass.

### Deployment readback, legacy comparison and cold/warm transactions

The full Foundry suite also executes `DeployDcapV2` itself in simulation, covering
staged configuration, legacy IDs/defaults, expected-current helper guards and
rollback. The readback runner separately checks all five transaction-deployed
runtimes (including immutable values), constructor getters, ownership, fees,
four reader authorizations, Router dependencies, IDs and the paused V2 state.

```bash
node scripts/fork-dcap-v2/manifest-readback.mjs \
  "$DCAP_RUN/deployment.json" "$DCAP_RUN/fork-manifest.json"
(cd evm && FOUNDRY_PROFILE=fork_osaka forge build forge-test/helpers/ForkGasProbe.sol)
node scripts/fork-dcap-v2/compare-gas.mjs \
  "$DCAP_RUN/deployment.json" "$DCAP_RUN/comparison.json" "$DCAP_VERIFIED_EVM_PROOF"
```

The probe is test-only and calls real verifiers twice in one transaction, checking
equal accepted outputs. Its first/repeated-call measurements include call/payment
overhead and warmed accounts/storage; they are not standalone transaction gas.
The comparison also records direct legacy/FeeV2-old/V2 raw receipts for V3/V4/V5,
helper rollback and legacy address/selector availability, then restores the exact
starting snapshot. Add any number of already crypto-verified EVM proof files for
ZK cold/warm measurements. Pass real proofs only; the report is not itself a
substitute for native or universal verifier proof validation.

Retain a compact derivative rather than committing full receipts/traces:

```bash
node scripts/fork-dcap-v2/summarize-gas.mjs \
  "$DCAP_RUN/gas.json" "$DCAP_RUN/comparison.json" "$DCAP_RUN/gas-summary.json" \
  "$DCAP_RUN/negative-gas.json"
```

Additional negative reports may follow the last argument. Source report hashes,
SDK transaction identifiers, calldata/intrinsic gas, exclusive component totals,
legacy/V2 differences and cold/warm pairs are retained. Positive ZK labels come
from the confirmed journal's quote version/body type, not a filename guess.
Component totals must reconcile to each receipt. They do not isolate every
internal Solidity function, and intrinsic gas is not added again to those totals.
The summary is evidence of measured local calls, not release approval.

After all six proof cells finish, reconcile their exact proof/program/journal
identity with the receipt-derived SDK/gas evidence:

```bash
node scripts/fork-dcap-v2/proof-matrix.mjs \
  "$DCAP_RUN/gas-summary.json" "$DCAP_RUN/proof-matrix.json" \
  "$DCAP_R0_SGX_PROOF" "$DCAP_R0_TDX_PROOF" "$DCAP_R0_V5_PROOF" \
  "$DCAP_SP1_SGX_PROOF" "$DCAP_SP1_TDX_PROOF" "$DCAP_SP1_V5_PROOF"
```

This expects 63 selected deployment/raw/ZK SDK transactions, six negative runs
and 15 cold/warm pairs from the complete recipe. It requires each real proof to
match four confirmed Go/Rust explicit/default transactions and its own rejection
run. It fails on missing/duplicate cells or hash mismatches. This offline
reconciliation is not a replacement for the preceding cryptographic/fork tests.
Keep the original `evm-proof.json` immutable: its `forkVerification: NOT_RUN`
describes the time of native export. Subsequent fork acceptance is recorded in
the SDK receipts and reconciled matrix, not by rewriting that source artifact.

Recover and check a bounded public legacy SP1 proof without retaining bulk logs:

```bash
node scripts/fork-dcap-v2/legacy-sp1-replay.mjs \
  "$DCAP_RUN/deployment.json" "$DCAP_RUN/legacy-sp1-replay.json"
```

This read-only runner fetches pinned Sepolia transaction
`0x77eb616e2eced89e1005f5df8f026b888ac96438c01ec2265bf9e795f1241db1`,
checks its successful canonical Fee event and historical program ID, then
verifies the recovered proof on the existing local gateway. Three cryptographic
negatives and old-Fee/FeeV2-old-selector behavior at six evaluation selections
are checked separately. At the September 14 fork state both Fee paths reject
the old collateral identically; this is not a legacy successful-attestation or
ATKJ proof result. No transaction is broadcast, even to the local node.

Timestamp-policy regression: raw uses the current block timestamp; ZK uses the
timestamp authenticated in its journal. Advancing the current block past signed
collateral expiry therefore rejects raw verification but does not alone reject
an otherwise valid historical proof. Changing the authenticated timestamp needs
a new proof; invalid pre-/post-validity inputs are rejected by the native/guest
tests. The fork harness must not invent an additional journal maximum-age rule.

## Resume real proofs, serially

Use the paired official Docker program artifacts, not unrelated host builds.
Both examples verify the original proof and complete journal before resuming.
The filenames below are operator-supplied paths to those existing artifacts.
Run only one proving/compression process at a time. Keep default circuit/FRI/VK
checks; `DEV_MODE`, insecure verifier overrides and newly generated setups are
not acceptance substitutes. `watch-proof.mjs` can stop an exact process family
on memory pressure; it is a polling guard, not a kernel-enforced RSS limit.
The SP1 Docker adapter retains the final witness and samples container memory
in its printed temporary handoff directory. Samples are not an exact peak;
host `time -v` RSS does not include a Docker-daemon-owned prover container.

```bash
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features risc0 --example risc0_v2_compress_local -- \
  "$DCAP_R0_PROGRAM" "$DCAP_INPUT" "$DCAP_R0_COMPOSITE" \
  "$DCAP_RUN/r0-succinct" succinct
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features risc0 --example risc0_v2_groth16_handoff -- \
  prepare "$DCAP_R0_PROGRAM" "$DCAP_INPUT" "$DCAP_RUN/r0-succinct/receipt.bin" \
  "$DCAP_RUN/r0-witness"
```

The prepare command uses unmodified `r0vm 3.0.3` to prepare `identity_p254`, then
expects the deliberately unavailable Docker connection to fail. That is witness
preparation only. Either use the pinned local ARM64 runner below or copy the
witness files plus checksums and the Mac runner to a Mac/AMD64 Docker machine
as in the supplied handoff package. For the latter, run:

```bash
bash risc0-groth16-mac.sh /absolute/witness-directory /absolute/new-result-directory
```

The official SDK image tag is resolved to a digest and executed without network
access. Return `return.tar.gz` even on proving failure. Verify its checksums, then:

```bash
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features risc0 --example risc0_v2_groth16_handoff -- \
  import "$DCAP_R0_PROGRAM" "$DCAP_INPUT" "$DCAP_RUN/r0-succinct/receipt.bin" \
  "$DCAP_RUN/r0-import" /absolute/returned/proof.json
```

The September 13 SGX return passes cryptographic import, the 13-test Sepolia
fork suite, a fresh 43-transaction Go/Rust raw/RISC Zero SDK replay with gas
reconciliation, and 17 additional control/negative/configuration transactions
followed by snapshot restoration. Its observed official index is
`risczero/risc0-groth16-prover@sha256:a4f80ce2e0b8e2bb7637a93c37136a6776ac00ec843a3fdf1c67b1d5ffea64ee`;
set `DCAP_R0_GROTH16_IMAGE` to this immutable reference when repeating the Mac
command. The runner explicitly selects Linux AMD64. An index-level Docker
inspection may leave OS/architecture blank: the registry index advertises AMD64
and ARM64 children. The ARM64 child passed TDX V4 final-stage proving,
independent cryptographic import, all 16 Sepolia tests and Go/Rust proof
transactions on September 14; no Mac is required for that run.
Do not infer either an x86-only requirement or ARM64 proof readiness from that
blank inspection field. Result checksums, original-input equality, local
cryptographic import and the existing on-chain verifier remain separate checks.

The local final-stage runner pins the platform manifest, disables network and
writes only into its new result directory, with a 7 GiB container memory cap:

```bash
docker pull --platform linux/arm64 \
  risczero/risc0-groth16-prover@sha256:55236d558d1e16e27f86f73237215c49f686521cab7652931c61c96d62cabcfc
bash scripts/fork-dcap-v2/risc0-groth16-local.sh \
  "$DCAP_RUN/r0-witness" "$DCAP_RUN/r0-docker-result"
```

Import `r0-docker-result/proof.json` with the same `import` command above, using
the original program/input/succinct receipt. `DCAP_R0_PLATFORM=linux/amd64` selects
the other reviewed manifest if needed; pull it explicitly first. A container exit
of zero is not proof acceptance until the independent importer and fork pass.

SP1 core → compressed can resume without generating the core proof again:

```bash
RAYON_NUM_THREADS=2 MALLOC_ARENA_MAX=2 \
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features sp1 --example sp1_v2_compress_local -- \
  "$DCAP_SP1_PROGRAM" "$DCAP_INPUT" "$DCAP_SP1_CORE" \
  "$DCAP_RUN/sp1-compressed" compressed
```

**SP1 parameter guard:** leave `FRI_QUERIES` **unset** for every stage. SP1 5.2.2
uses core/inner 100, shrink 50 and outer 25 queries at different blowup factors.
Exporting `FRI_QUERIES=100` changes shrink and outer too; it is not equivalent
to official defaults and is incompatible with the existing Groth16 circuit.
The helpers reject any override, including 100 or an empty value. The earlier
September 14 Mac handoff that forwarded 100 is obsolete: its outer proof can
verify under that overridden configuration but must not enter release
acceptance. See the execution record for the actual witness-size rejection.
Regenerate shrink/outer from a compressed proof reverified under official
defaults; never create a new setup to accommodate the overridden parameters.

The final SP1 stage requires the **existing official** v5.0.0 circuit bundle:

```bash
curl --fail --location --output "$DCAP_RUN/sp1-v5.0.0-groth16.tar.gz" \
  https://sp1-circuits.s3-us-east-2.amazonaws.com/v5.0.0-groth16.tar.gz
node scripts/fork-dcap-v2/prepare-sp1-circuits.mjs \
  "$DCAP_RUN/sp1-v5.0.0-groth16.tar.gz" "$DCAP_RUN/sp1-circuits/v5.0.0"
```

Downloading/checking the setup is not proof verification. Shrink, BN254 wrapping
and the compatible gnark runtime still need to complete; do not claim a compressed
SP1 proof or succinct RISC Zero receipt is ready for an EVM route.

On ARM64, the official gnark v5.0.0 manifest is
`ghcr.io/succinctlabs/sp1-gnark@sha256:7a7505bf609f3646cc058134bf016827af3af6a8d42f257fb77ac635448a8b65`.
If daemon pulls fail while client registry access works, a verified fallback is
[crane v0.20.3](https://github.com/google/go-containerregistry/releases/tag/v0.20.3)
`pull --platform linux/arm64 IMAGE NEW_ARCHIVE.tar`, followed by `docker load`.
Compare the archive config's runtime fields and rootfs digests to the loaded
image; the Docker import can convert the manifest identity. Record both IDs.
Use the **verified local immutable image ID**, not a mutable convenience tag:

```bash
PATH="$PWD/scripts/fork-dcap-v2/sp1-runtime:$PATH" \
SP1_GNARK_IMAGE="$DCAP_VERIFIED_GNARK_IMAGE_ID" \
SP1_GROTH16_CIRCUIT_PATH="$DCAP_RUN/sp1-circuits" \
DCAP_GNARK_MEMORY=11g \
RAYON_NUM_THREADS=2 MALLOC_ARENA_MAX=2 \
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features sp1 --example sp1_v2_compress_local -- \
  "$DCAP_SP1_PROGRAM" "$DCAP_INPUT" "$DCAP_RUN/sp1-compressed/compressed.bin" \
  "$DCAP_RUN/sp1-groth16" groth16
```

The task-scoped adapter defaults to 9 GiB / 2 CPUs; the successful acceptance run
needed the explicit 11 GiB override above (9 GiB caused Docker OOM). Allocate
enough host headroom; do not blindly use this cap on a smaller machine. It runs
as the host UID/GID so a mode-0600 witness is readable without extra capabilities,
disables network access, mounts the setup read-only and refuses setup/build commands.
Do not place it on a global PATH. Run this only after the previous proving job
has stopped; a memory guard should monitor both host and container resource use.
To bound combined memory, stop before gnark with the `outer` stage in one
process, then run the final stage in a fresh process:

```bash
RAYON_NUM_THREADS=2 MALLOC_ARENA_MAX=2 \
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features sp1 --example sp1_v2_compress_local -- \
  "$DCAP_SP1_PROGRAM" "$DCAP_INPUT" "$DCAP_RUN/sp1-compressed/compressed.bin" \
  "$DCAP_RUN/sp1-outer" outer
```

Use the earlier gnark command with a new result directory and append
`"$DCAP_RUN/sp1-outer/outer.bin"`. The `outer` checkpoint is not an EVM proof;
the final SDK verification still checks its complete expected journal binding.
If only the final gnark stage failed, append the previous `outer.bin` as the
last argument and use a new output directory. The runner rederives the expected
wrap verifying key from the pinned SDK and verifies the checkpoint before reuse.
The adapter retains a small witness/checksum package under `/tmp` for diagnosis;
it does not treat witness preparation as successful proof verification.

When final proving must be separated from the host process, use a retained
witness generated from an outer proof that passed the **official-default**
checks. `sp1-gnark-local.sh` rechecks the fixed setup hashes, waits for memory
headroom and runs only the official container's `prove` command. It never
builds circuits or performs setup. It also compares witness dimensions to the
hash-verified official template, rejecting noncanonical layouts before allocating
proving memory. The reviewed image embeds Go 1.22.12; the standalone runner uses
`GOMAXPROCS=1`, `GOGC=50`, and the soft `GOMEMLIMIT=8GiB` to reduce transient heap
growth. These are runtime memory/CPU controls, not FRI or circuit overrides.
The container hard cap remains 11 GiB with no container swap, plus a 1.5 GiB
system-availability watchdog; the Go soft limit is not a hard RSS bound.
The final importer rechecks the original
compressed proof, the native program ID and full expected journal, verifies
Groth16 and tamper negatives, and exports an immutable EVM payload:

```bash
bash scripts/fork-dcap-v2/sp1-gnark-local.sh \
  "$DCAP_VERIFIED_WITNESS_DIR" "$DCAP_RUN/sp1-circuits/v5.0.0" "$DCAP_RUN/gnark-final"

PATH="$PWD/scripts/fork-dcap-v2/sp1-runtime:$PATH" \
SP1_GNARK_IMAGE="$DCAP_VERIFIED_GNARK_IMAGE_ID" \
SP1_GROTH16_CIRCUIT_PATH="$DCAP_RUN/sp1-circuits" \
RAYON_NUM_THREADS=1 MALLOC_ARENA_MAX=2 \
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-zkvm --features sp1 --example sp1_v2_import_gnark -- \
  "$DCAP_SP1_PROGRAM" "$DCAP_INPUT" "$DCAP_RUN/sp1-compressed/compressed.bin" \
  "$DCAP_RUN/gnark-final/gnark-proof.bin" "$DCAP_RUN/gnark-imported"
```

The container result is a pinned gnark transport envelope, not an SDK proof or
an EVM payload. The importer rejects malformed/trailing data and other proof
families. Native SDK checks bind the raw proof and public inputs; the emitted
encoded EVM bytes still must pass the existing universal verifier/FeeV2 gate.
The task-scoped Docker adapter retains the actual successful gnark transport
output as well as its witness, allowing this importer to be tested even when
the original host process already completed native SDK verification.

If BN254 outer wrapping exceeds available host memory, first reduce only
`RAYON_NUM_THREADS` to `1` and retry in a fresh directory from the verified
compressed checkpoint. Keep the memory watchdog and all circuit/FRI parameters.
Do not overwrite earlier checkpoints, interpret a memory-guard exit as a
cryptographic rejection, disable verification or create a new trusted setup.

`sp1-outer-container.sh` provides a bounded ARM64 checkpoint handoff when a
larger machine is needed. Its input directory contains the already-built Linux
ARM64 `helper` (`sp1_v2_compress_local`), canonical `program.elf`, frozen
`input.bin`, verified `compressed.bin` and `SHA256SUMS`. Record the helper source,
host lock/compiler and guest native ID alongside the package. On the receiving
machine, independently check these hashes against the sender's record.

```bash
docker pull --platform linux/arm64 \
  ubuntu@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254
bash scripts/fork-dcap-v2/sp1-outer-container.sh \
  "$DCAP_HANDOFF" "$DCAP_NEW_OUTER_RESULT"
```

This fixed Ubuntu image is only a host-helper runtime, **not a new guest
reproducible-build image or proving setup**. Its helper-loading preflight passes
on the current ARM64 host; a full outer run with the corrected no-override
recipe has not yet been repeated in this container. The earlier Mac run used
the obsolete override described above. Apple Silicon can run this ARM64 runtime without Rosetta.
The script requires at least 16 GiB assigned to Docker and caps the container
at 14 GiB, so an 8 GiB Docker Desktop VM must be increased first on an otherwise
idle, sufficiently large machine. Networking and Docker socket access are
disabled; input mounts are read-only. Return the result directory, including
logs and checksums on failure. After a successful return, resume the separate
Groth16 stage locally with the original compressed proof and returned
`outer/outer.bin`; the SDK must independently verify that checkpoint and the
final journal. An outer checkpoint alone does not close the fork gate.

## Real EVM-proof fork gate

Only use an `evm-proof.json` exported after cryptographic verification, never a
mock payload. Place it in ignored `evm/forge-test/assets/v2/local-fork/`, then add
these variables to the Foundry command above:

```bash
DCAP_FORK_PROOF_FILE=forge-test/assets/v2/local-fork/r0-sgx-evm-proof.json
DCAP_FORK_FIXTURE=ata-sgx-v3
```

They must be exported or supplied on the same command invocation. The test calls
the fork's existing universal verifier and new FeeV2, and covers altered proof,
journal, format, IDs, framing, evaluation, pause and route freeze. No proof file
means an explicit skip, **not** a successful real-proof gate. Each backend and
quote-layout cell, SDK ZK transactions and rollback still needs its own result.

After the real proof gate, the SDK runners exercise the same proof on the local
Anvil deployment, including both signed transaction overloads and exact events.
They restore the original ZK pause setting even when a check fails:

```bash
# From go-sdk/; use absolute paths.
DCAP_ANVIL_REPORT="$DCAP_RUN/deployment.json" \
DCAP_EVM_PROOF="$DCAP_VERIFIED_EVM_PROOF" \
DCAP_ZK_SDK_REPORT="$DCAP_RUN/go-zk.json" \
go test ./packages/godcap/attestationv2 -run '^TestForkRealZKV2SDK$' -count=1 -v

# From the repository root; no concurrent writes to this Anvil instance.
cargo run --release --locked --manifest-path rust-crates/Cargo.toml \
  -p automata-dcap-verifier --example fork_v2_zk_sdk -- \
  "$DCAP_RUN/deployment.json" "$DCAP_VERIFIED_EVM_PROOF" "$DCAP_RUN/rust-zk.json"
node scripts/fork-dcap-v2/gas-report.mjs \
  "$DCAP_RUN/deployment.json" "$DCAP_RUN/go-raw.json" "$DCAP_RUN/rust-raw.json" \
  "$DCAP_RUN/go-zk.json" "$DCAP_RUN/rust-zk.json" "$DCAP_RUN/gas-with-zk.json"
```

These SDK proof fixtures currently require evaluation 20 and the exact Sepolia
fork origin. A missing proof makes the Go test explicitly skip, not pass.
Proof generation is randomized: compare cryptographic validity and exact native
ID/journal, not independently generated proof bytes. Paired build ELF/native-ID
equality remains a separate reproducibility check.
