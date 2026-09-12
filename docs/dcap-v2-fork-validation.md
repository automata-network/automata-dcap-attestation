# DCAP V2 fork acceptance TODO — required, not started

This is a mandatory pre-release phase, deferred at the user's request until
the current fixture, reproducible-build and real-proof prerequisites are
resolved. Do not start forks or broadcast deployment transactions as part of
recording this checklist. Obtain the user's go-ahead before starting this phase.
Passing local unit tests or mock-verifier tests does not close these items.

Production scope is the existing network/backend matrix: RISC Zero/SP1 only
where already supported. Pico is local-only by the user's 2026-09-11 decision;
no Pico deployment, V2 registration/default/route, network SDK enablement or
production gas target is included. Record those cells as **N/A — local-only**,
not as passed or as missing production coverage. Pico local proof testing is
tracked separately and does not block this fork phase or production release.

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
- [ ] Produce and locally verify the intended EVM-compatible proof formats
  for the release matrix. Composite/core proofs cannot be passed directly to
  the deployed universal verifiers. No mock proofs, DEV_MODE, cached unrelated
  proofs or paid network proving without separate authorization.
- [ ] Use the checked-in V3/V4/V5 quote/collateral fixtures as a deterministic
  baseline. Source additional signed inputs/collateral appropriate to each
  fork's block timestamp; historical success is not evidence of current validity.
  Include the authenticated ATA SGX V3 and extracted TDX V4 inputs from the
  [public-quote validation record](dcap-v2-public-quotes-validation.md), with
  their full signed collateral and frozen journals at timestamp `1789139978`.
  Preserve the original 8,000-byte padded TDX as a rejection case, not a success
  input. SGX returns `OutOfDate`; both samples use Platform CA with PIID present,
  so they do not supply Processor CA/PIID-absent or V5 coverage.
- [ ] Define the target-chain list, RPCs, pinned fork block numbers/hashes, chain
  IDs, client versions and snapshot/reset strategy. Record credentials only in
  secrets, never in the report or manifest. No production writes.

## 2. Live configuration inventory and release manifest

- [ ] Fill `dcap-v2-release-manifest.example.json` from observed state for every
  target chain: deployment addresses, code hashes, owners and authorized callers.
- [ ] Inventory all six Router components and versioned DAO/evaluation-number
  mappings. Check reused P-256, CRL/TCB helpers, DAOs and storage dependencies.
- [ ] Enumerate every needed legacy program ID, including ATKJ compact programs,
  legacy/V2 defaults, universal verifier addresses, all proof-selector routes and
  security freezes. Inspect historical events/configuration for non-enumerable
  mappings; default routes alone are not a complete inventory.
- [ ] Record fee recipients, fee settings/basis points, pause states and any
  per-chain differences. Compare the migration plan against the live values.
- [ ] Confirm no network/backend expansion: unsupported backends stay disabled
  and no Pico V2 default, route or program ID is introduced. Report unexpected
  live Pico configuration for a scope decision rather than deleting legacy state.

## 3. Deployment, staged migration and rollback

- [ ] Deploy PCKHelperV2, V3/V4/V5 verifier instances and FeeV2 on each fork;
  verify bytecode, EIP-170 size limits, constructor settings and ownership.
- [ ] Replay staged deployment/configuration, Router caller authorization for
  all four new readers, legacy IDs/routes/fees migration and V2 registration.
  Keep V2 ZK paused until checks pass. Exercise wrong-owner and missing-role cases.
- [ ] Switch only `pckHelper`, preserving the five other live Router values.
  Exercise expected-current checks and concurrent/stale configuration scenarios.
- [ ] Read back the complete configuration and compare against the manifest;
  prove that old IDs, freezes, routes and legacy callers remain operational.
- [ ] Exercise V2 pause/unpause, caller address migration and rollback: stop V2
  traffic, restore the old helper/client address, preserve collateral/history,
  and verify expected legacy availability and V2 unavailability after rollback.

## 4. Raw quote verification

- [ ] Cover authentic V3/V4/V5 success where each supported SGX/TDX body layout
  has a signed fixture; explicitly report missing combinations rather than
  treating synthetic serialization tests as authenticated verification.
- [ ] Cover automatic and explicit TCB evaluation-number selection, PCS API v4 /
  TCB Info v3, matched advisory IDs, certificate/CRL/identity validity and status.
- [ ] Compare complete OutputV2 bytes with native Rust at the identical timestamp
  and collateral; check PPID, PIID/presence, CA semantics, format 2.1, event fields
  and legacy output/selector coexistence.
- [ ] Reject malformed/truncated inputs, invalid signatures, revoked/expired or
  missing collateral, invalid production attributes and migration-service TDs.
  Check error behavior and no accepted output/event for rejected attestations.
- [ ] Run the previously excluded `CrlV2AeneidForkTest`, record the pinned block
  and RPC/network assumptions, and investigate differences instead of skipping it.

## 5. Real ZK verification

- [ ] For RISC Zero/SP1 on their existing supported networks, verify newly
  generated real V2 proofs with the target chain's actual reused universal
  verifier and FeeV2 routes/defaults.
  Cover every proof format/selector intended for release, not just one default.
- [ ] Cover quote-version/body layouts and chain/backend combinations in an
  explicit matrix; record untested cells. Verify output/journal/event parity
  with raw verification using the same verification timestamp and collateral.
- [ ] Reject wrong program IDs, wrong program family, modified proof/journal,
  invalid framing, unsupported output versions, stale/invalid collateral,
  frozen routes and paused V2 verification. No mock universal verifier substitutes.
- [ ] Replay legacy proof registrations, including ATKJ compact journals, through
  their intended legacy paths. Legacy and V2 defaults must not cross families.

## 6. Supported SDK end-to-end coverage

- [ ] Rust: registry/version/address selection, collateral acquisition and input
  encoding, supported RISC Zero/SP1 host backends, raw/ZK FeeV2 calls, output parsing, events,
  errors, fee calculation and transaction receipt handling against the forks.
- [ ] Go: supported collateral/quote APIs, registry/bindings, raw/ZK transaction
  paths and supported proving-service integrations, OutputV2/event parsing and
  errors. Feed backend proofs via the SDK where no native prover integration
  exists; mark capability gaps explicitly. Pico stays outside network SDK
  acceptance; retain its local SDK regressions without claiming a Go Pico prover.
- [ ] Validate all SDK-exposed overloads, explicit/automatic evaluation selection,
  caller permissions and migration/rollback address selection.
- [ ] Keep Solana excluded as agreed. TeeVerifier/application adoption requires
  an explicitly agreed application test target; do not silently change or deploy
  downstream application contracts while validating this repository's SDKs.

## 7. Gas and off-chain cost breakdown

- [ ] Record deployment gas per new contract and configuration gas per operation:
  authorization, ID/route migration, pause, helper switch and rollback.
- [ ] Separate collateral ingestion/update gas from per-quote verification gas.
  Break raw verification down by V3/V4/V5 and body type, parsing, certificate/CRL
  and TCB checks, output/event handling, cold/warm state and cached/uncached data.
- [ ] Break ZK gas down by backend/proof format, calldata bytes, universal verifier
  call, FeeV2 journal/collateral policy checks, events and fees; include failures.
- [ ] Use transaction receipts plus traces for top-level and internal gas.
  Identify intrinsic/calldata costs separately and avoid double-counting nested
  calls. Unit-test method gas includes assertions and is not a transaction quote.
- [ ] Report L1/L2 data fees where relevant, pricing assumptions and absolute /
  relative legacy-vs-V2 differences on the same fork. Do not invent current prices.
- [ ] Separately measure SDK/network latency, native verification, guest execution,
  proof generation time and peak memory. CPU cycles and wall time are not gas.

## 8. Deliverables and release decision

- [ ] Commit a rerunnable fork harness, pinned configurations, input/proof
  provenance, pass/fail matrix, gas tables/traces and rollback evidence.
- [ ] Re-run from a fresh fork snapshot through supported SDK entry points and
  reconcile deployment/configuration receipts against the release manifest.
- [ ] Resolve unexplained failures or missing release-critical coverage before
  proposing a live rollout. Publication, broadcast and changing SDK defaults
  remain separately approved release actions.
