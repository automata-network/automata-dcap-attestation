# DCAP V2 fork acceptance — scoped V2 E2E complete; release gates open

The user authorized this phase on 2026-09-12, including off-chain preparation
of real EVM-compatible proofs and deployment/integration inside forked networks.
Proof generation/compression and fork preparation may proceed within the same
phase; a successful real-proof test still requires the actual completed proof.
No live deployment, broadcast, paid remote proving or network/backend expansion
is authorized. All deployment/configuration transactions execute only locally.
Passing local unit tests or mock-verifier tests does not close these items.

The six-cell V2 / single-Sepolia result is recorded in the
[acceptance summary](dcap-v2-sepolia-acceptance.md) and
[proof matrix](dcap-v2-sepolia-proof-matrix.json). Historical execution results
and explicitly unclosed gaps remain in [dcap-v2-fork-progress.md](dcap-v2-fork-progress.md).
This completes the scoped V2 E2E, not every broader release or legacy follow-up
below. Explicit skips and absent coverage never count as passes.

Production scope is the existing network/backend matrix: RISC Zero/SP1 only
where already supported. Pico is local-only by the user's 2026-09-11 decision;
no Pico deployment, V2 registration/default/route, network SDK enablement or
production gas target is included. Record those cells as **N/A — local-only**,
not as passed or as missing production coverage. Pico local proof testing is
tracked separately and does not block this fork phase or production release.

## Scope clarification — 2026-09-14

The user requires **one representative fork for complete E2E**, not a full
replay on every supported network. Use Ethereum Sepolia (chain 11155111), where
both existing RISC Zero and SP1 verifiers have already accepted V2 proofs.
Retain block 11689923, hash
`0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096`,
Osaka execution and Paris contract bytecode. Recreating this same pinned fork
for independent scenarios or a clean replay does not add another network.

The complete deployment/configuration/upsert/raw/ZK/SDK/negative/rollback/gas
workflow is required on that fork. The three authenticated proof inputs are
`ata-sgx-v3.json`, `ata-tdx-v4.json`, and Google's `v5.json`, for both backends.
Reuse their signed collateral, frozen verification times
and expected journals; no new quote is needed for those three cells. The
original padded TDX input remains a negative fixture, with no runtime trimming.

Before an actual production rollout, read back each **selected deployment
target's** chain ID, code hashes, addresses, owners/permissions, Router values,
IDs/routes/freezes and fees. This is configuration preflight, not repeated full
E2E on all 28 registry networks. Scope/behavior differences require an explicit
decision or focused check, not automatic network/backend expansion. Previously
collected Hoodi/mainnet/OP results are supplementary evidence; their untested
E2E cells and L2 total-fee estimates do not block the selected Sepolia E2E.
The previously requested Story CRL historical regression remains a separate
focused follow-up; it is not silently marked passed or canceled by this change.

## 1. Entry conditions and reproducible environment

- [x] Paired clean container builds for all three backends at frozen source
  `81646e5` match in bytes/native IDs using the same fixed image/platform, not
  host/Docker equality; RISC Zero/SP1 use official images. See the
  [evidence record](dcap-v2-container-rebuild.md).
- [ ] Freeze final release source and
  PCCS commits, host/guest lock hashes, compiler identities, container digest,
  build commands, artifact SHA-256 values and independently computed native IDs.
  Repeat build/execution checks if guest source, dependencies or recipe change.
- [x] Generate real local RISC Zero composite and SP1 core V2 proofs with the
  pinned Docker programs and confirm cryptographic verification: both pass for
  ATA SGX V3, including full journal equality and three tampering/wrong-ID or
  key rejection checks per backend. See the [extended serial retry](dcap-v2-public-quotes-validation.md#extended-serial-retry-2026-09-11).
  This establishes neither TDX/V5 real-proof coverage nor EVM proof compatibility.
- [x] Produce and locally verify the intended EVM-compatible proof formats
  for the scoped three-fixture/two-backend matrix. Composite/core proofs cannot be passed directly to
  the deployed universal verifiers. No mock proofs, DEV_MODE, cached unrelated
  proofs or paid network proving without separate authorization.
  All six cells pass local cryptographic verification, existing-verifier/FeeV2
  forks, both SDKs and proof/journal identity reconciliation. SP1 V5 completed
  on September 14 after fixing the runner's global FRI override; only official
  defaults and the existing official setup are accepted. The scoped formats are
  RISC Zero `73c457ba` and SP1 `a4594c59` Groth16. The pinned SP1 v5 Plonk
  route is absent; this phase does not add it or claim Plonk acceptance.
- [x] Use the checked-in V3/V4/V5 quote/collateral fixtures as a deterministic
  baseline. Source additional signed inputs/collateral appropriate to each
  fork's block timestamp; historical success is not evidence of current validity.
  Include the authenticated ATA SGX V3 and extracted TDX V4 inputs from the
  [public-quote validation record](dcap-v2-public-quotes-validation.md), with
  their full signed collateral and frozen journals at timestamp `1789139978`.
  Preserve the original 8,000-byte padded TDX as a rejection case, not a success
  input. SGX returns `OutOfDate`; both samples use Platform CA with PIID present,
  so they do not supply Processor CA/PIID-absent or V5 coverage.
- [x] Select the single E2E chain and record its RPC, pin/hash, execution rules
  and snapshot/reset strategy: Sepolia as specified above and in the runner
  recipes. Record credentials only in secrets, never in reports. No production writes.

## 2. Live configuration inventory and release manifest

- [x] Fill the Sepolia E2E manifest from observed state: deployment addresses,
  code hashes, owners and authorized callers. Before any actual rollout, perform
  separate configuration preflight for the selected production targets; no
  all-registry-network E2E requirement is implied. The checked-in local manifest
  records the observed fork state, not a frozen production release manifest.
- [x] Inventory all six Router components and versioned DAO/evaluation-number
  mappings. Check reused P-256, CRL/TCB helpers, DAOs and storage dependencies.
- [ ] Enumerate every needed legacy program ID, including ATKJ compact programs,
  legacy/V2 defaults, universal verifier addresses, all proof-selector routes and
  security freezes. Inspect historical events/configuration for non-enumerable
  mappings; default routes alone are not a complete inventory.
- [x] Record fee recipients, fee settings/basis points, pause states and any
  per-chain differences. Compare the migration plan against the live values.
- [x] Confirm no network/backend expansion: unsupported backends stay disabled
  and no Pico V2 default, route or program ID is introduced. Report unexpected
  live Pico configuration for a scope decision rather than deleting legacy state.

## 3. Deployment, staged migration and rollback

- [x] Deploy PCKHelperV2, V3/V4/V5 verifier instances and FeeV2 on the Sepolia fork;
  verify bytecode, EIP-170 size limits, constructor settings and ownership.
- [x] Replay staged deployment/configuration, Router caller authorization for
  all four new readers, legacy IDs/routes/fees migration and V2 registration.
  Keep V2 ZK paused until checks pass. Exercise wrong-owner and missing-role cases.
- [x] Switch only `pckHelper`, preserving the five other live Router values.
  Exercise expected-current checks and concurrent/stale configuration scenarios.
- [x] Read back all deployed runtimes/immutables, owners, Router components,
  reader authorizations, fee/pause settings and enumerated legacy/V2 IDs against
  the local manifest. The universal routers are reused unchanged; known route
  and freeze guards pass. This is not proof of exhaustive unenumerable route
  history or a successful replay of every historical legacy/ATKJ proof; those
  applicability and replay gaps remain explicitly tracked below.
- [x] Exercise V2 pause/unpause, caller address migration and rollback: stop V2
  traffic, restore the old helper/client address, preserve collateral/history,
  and verify expected legacy availability and V2 unavailability after rollback.

## 4. Raw quote verification

- [x] Cover authentic V3/V4/V5 success where each supported SGX/TDX body layout
  has a signed fixture; explicitly report missing combinations rather than
  treating synthetic serialization tests as authenticated verification.
  Authenticated cells are SGX V3, TDX V4 and TDX 1.5 V5, all Platform CA with
  PIID present. SGX V4/V5, TDX 1.0 V5 and Processor CA/PIID-absent have no
  authenticated success fixture in this matrix; parser/unit tests are not a
  substitute for those real hardware combinations.
- [x] Cover automatic and explicit TCB evaluation-number selection, PCS API v4 /
  TCB Info v3, matched advisory IDs, certificate/CRL/identity validity and status.
- [x] Compare complete OutputV2 bytes with native Rust at the identical timestamp
  and collateral; check PPID, PIID/presence, CA semantics, format 2.1, event fields
  and legacy output/selector coexistence.
- [x] Reject scoped malformed/truncated/padded inputs, signed-body mutations and
  expired/invalid-evaluation collateral; check false versus revert behavior and
  absence of accepted events. Production-policy unit/native/guest regressions
  supplement the fork. Mutating a signed debug bit only tests signature rejection;
  it is not an authenticated debug-policy fixture. The signed Alibaba migration
  TD fixture reaches `TCBR` first on Sepolia; its exact migration-policy rejection
  is separately observed on Hoodi. Do not infer every revocation/policy permutation.
- [ ] Separate focused follow-up: finish the previously requested
  `CrlV2AeneidForkTest`, recording its historical pin/RPC limitations. This is
  not a second full-network E2E requirement; do not claim skipped/pruned cases pass.

## 5. Real ZK verification

- [x] For both RISC Zero and SP1 on the selected Sepolia fork, verify newly
  generated real V2 proofs with that chain's actual reused universal
  verifier and FeeV2 routes/defaults.
  Cover every proof format/selector intended for release, not just one default.
- [x] Cover the three authenticated quote-version/body layouts and both backends on Sepolia in
  an explicit matrix; record untested cells. Verify output/journal/event parity
  with raw verification using the same verification timestamp and collateral.
- [x] Reject wrong program IDs, wrong program family, modified proof/journal,
  invalid framing, unsupported output versions, stale/invalid collateral,
  frozen routes and paused V2 verification. No mock universal verifier substitutes.
  Collateral validity is checked at the authenticated journal timestamp. Merely
  advancing submission time does not invalidate a historical proof; the real
  fork regression explicitly preserves the agreed absence of a maximum-age
  policy. Native/guest pre-/post-validity input mutations must reject.
- [ ] Replay legacy proof registrations, including ATKJ compact journals, through
  their intended legacy paths. Legacy and V2 defaults must not cross families.

## 6. Supported SDK end-to-end coverage

- [x] Rust: explicit fork-address/version selection, collateral acquisition and input
  encoding, local RISC Zero/SP1 host backends, raw/ZK FeeV2 calls, output parsing, events,
  errors, fee calculation and transaction receipt handling against the Sepolia fork.
- [x] Go: V2 collateral/quote APIs, bindings with explicit local addresses, raw/ZK transaction
  paths consuming locally verified backend proofs, OutputV2/event parsing and
  errors. Feed backend proofs via the SDK where no native prover integration
  exists; mark capability gaps explicitly. Pico stays outside network SDK
  acceptance; retain its local SDK regressions without claiming a Go Pico prover.
- [x] Validate supported local raw/ZK binding overloads, explicit/automatic evaluation selection,
  caller permissions and migration/rollback address selection.
- [ ] Release follow-up: promote live registry addresses/defaults only after
  deployment approval; remote proving services and their legacy defaults were
  not changed or exercised as V2 services in this local acceptance.
- [x] Keep Solana excluded as agreed. TeeVerifier/application adoption requires
  an explicitly agreed application test target; do not silently change or deploy
  downstream application contracts while validating this repository's SDKs.

## 7. Gas and off-chain cost breakdown

- [x] Record deployment gas per new contract and configuration gas per operation:
  authorization, ID/route migration, pause, helper switch and rollback.
- [x] Separate signed collateral upsert transactions from per-quote verification.
  Report raw V3/V4/V5 receipt gas, exclusive parser/CRL/TCB/DAO/storage/verifier
  buckets and cold/warm repeated calls. Private certificate/policy functions and
  event handling are within aggregate buckets, not separately instrumented.
  Cached entries skipped by bootstrap are not measured as uncached writes.
- [x] Break ZK gas down by backend/proof format, calldata bytes, universal verifier
  call, FeeV2 journal/collateral policy checks, events and fees; include failures.
- [x] Use transaction receipts plus traces for top-level and internal gas.
  Identify intrinsic/calldata costs separately and avoid double-counting nested
  calls. Unit-test method gas includes assertions and is not a transaction quote.
- [x] Report transaction/calldata gas, pricing assumptions and absolute /
  relative legacy-vs-V2 differences on the same Sepolia fork. L2 data/operator
  fees are outside this single-L1 E2E gate; do not extrapolate Sepolia gas into
  other chains' total fees or invent current prices.
- [x] Record observed SDK/acquisition timings, native/guest checks, serial proof
  times and process/container memory in the execution records. Sampled Docker
  maxima are not exact RSS peaks; these observations are not a controlled
  cross-backend latency benchmark. CPU cycles and wall time are not gas.

## 8. Deliverables and release decision

- [x] Prepare rerunnable fork/proof harnesses, pins, input/proof provenance,
  compact pass/fail matrix, gas tables and rollback/readback evidence. Full
  proofs, receipts/traces and logs remain ignored/local, not bulk Git payloads.
- [ ] Review and commit the prepared changes; freeze the final release source
  and manifest. No staging or commit is implied by test execution.
- [x] Re-run from a fresh same-pin fork through supported SDK entry points and
  reconcile all six cells and deployment/configuration receipts against the
  local manifest: 63 selected transactions, 29 comparison transactions, six
  negative runs / 66 rejections, with snapshot restoration and V2 paused.
- [ ] Resolve unexplained failures or missing release-critical coverage before
  proposing a live rollout. Publication, broadcast and changing SDK defaults
  remain separately approved release actions.
