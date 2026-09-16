# DCAP V2 rollout (not executed)

## Current revision gate

The minCheck/Keccak revision invalidates earlier draft V2 guest/proof acceptance.
Do not register the historical SHA-256 fullQuoteHash guest IDs in the revised
FeeV2. Rebuild with pinned Docker images, compute new native IDs, regenerate
RISC Zero/SP1 proofs and repeat Sepolia raw/ZK/SDK/gas acceptance for this source.
Keep legacy V1 IDs in their separate legacy registry. See
[current mode semantics and regression](dcap-v2-min-check.md).

## Release scope (confirmed 2026-09-11)

- Preserve the existing network/backend support matrix. RISC Zero/SP1 are the
  production candidates only on networks that already support the respective
  backend; this release does not add backend support to other networks.
- Pico remains **local-only**. Do not deploy a Pico universal verifier, register
  a new Pico V2 program/default/route, or publish/enable Pico network endpoints.
  Keep its source and local SDK/build/execution tests; local proof verification
  is tracked separately and is not a production release blocker.
- Recovering parameters for an assumed deployed Pico verifier is not a release
  prerequisite. A local proof test needs a matching local circuit/key/verifier
  set, not compatibility with an unverified production deployment. No new setup
  or deployment is performed merely by recording this scope.

## Implementation details

- Five new deployments: PCKHelperV2, V3/V4/V5QuoteVerifierV2, FeeV2. PCCS DAOs/storage, CRL/FMSPC helpers, P-256 and universal proof verifiers are reused.
- Canonical output serialization and V2 journal/collateral validation live in FeeV2 to meet EIP-170. Quote verifiers return an internal ABI envelope to FeeV2; that envelope is never an application output or journal.
- The shared Router must authorize FeeV2 as well as all three quote verifiers when caller restrictions are enabled.
- Legacy selectors retain the old parser, acceptance policy, output, events, and program family. V2 uses the strict identity parser and Rust production quote policy, including debug, TDX attribute and migration-service checks. V2 rejects trailing quote/authentication bytes.
- Legacy and V2 program IDs/defaults are independent. Universal proof-selector routes/security freezes are shared. V2 can be paused independently without touching old IDs/routes.
- Host V2 selection is explicit: use version v2.0 and DCAP_V2_ELF pointing to the backend-specific audited artifact. The artifact's native identifier must match the release manifest, not merely its ELF SHA-256.

## Gates and ordering

On 2026-09-14 the user clarified that complete E2E is required on **one fork**:
Ethereum Sepolia, covering both existing production-candidate ZK backends.
Do not require a full E2E/gas/rollback replay on every supported network.
Read-only configuration preflight for each selected production deployment
target remains a separate rollout safety check; existing support is not expanded.

1. PCCS parser changes are committed and the DCAP submodule is pinned to `f1406ef479560ad888960899b95383f026c76526`. Preserve that pin in the release manifest; the sibling checkout was not edited.
2. Finalize guest toolchains, lockfiles and digest/platform-pinned Docker images. Paired clean builds for all three backends already pass at source `81646e5`; freeze the final release inputs and repeat if guest source, dependencies or the build recipe change. Compare complete artifacts/native IDs without requiring host-native equality, using the official RISC Zero/SP1 images. For production-enabled RISC Zero/SP1 routes, prove real quotes and verify against the intended existing universal verifiers and FeeV2. Execution-only runs and mocks do not satisfy that proof gate. Pico proof testing remains local-only and outside this production gate.
3. Fill the release manifest from live state. Inventory every required legacy ID, including ATKJ compact programs, plus default IDs, proof-selector routes/freezes, fee basis points and all six Router components. Mapping routes require historical event/config inspection; do not assume the default verifier covers every route.
4. Simulate DeployDcapV2 stages on the representative Sepolia fork. Deploy five new contracts. Configure only FeeV2 and authorize the four new readers; copy legacy fee configuration, IDs and routes. Keep V2 ZK paused while staging. For later selected deployment targets, compare their live configuration with the validated recipe; investigate material differences without automatically repeating full E2E everywhere.
5. Register separately audited RISC Zero/SP1 V2 native IDs only for backends already supported on the target network, against reused universal verifiers. Do not add Pico IDs/defaults/routes. Re-read configuration and compare the exact old/default ID sets and route states to the manifest; investigate unexpected live backend configuration before changing scope.
6. Switch only the Router's pckHelper, using the live values of the other five fields. Coordinate with the Router owner to avoid concurrent configuration updates between simulation and execution. Read back all six components.
7. Run legacy and V2 on-chain/ZK regressions and transaction-event checks. Enable V2 ZK only after the release gates pass. Update application addresses explicitly; no application is migrated by these scripts.
8. Publish real addresses under deployment/v2.0 and additive *V2 keys. The pre-upgrade deployment/v1.1 snapshot is checked in; current still denotes v1.1. Promote current and SDK defaults only in the release PR after approval. Do not replace the old keys or old embedded ELFs.

## Rollback

- Stop V2 clients and set FeeV2.setZkV2Paused(true). Preserve all legacy IDs and universal proof routes.
- Repoint clients to the old Fee deployment when needed.
- Use switchHelper with expectedCurrent=PCKHelperV2 and replacement=the recorded old helper, preserving all other live Router components.
- After restoring the old helper, V2 on-chain identity calls are unavailable; legacy selectors continue to use the old method.
- Retain new deployments/artifacts and transaction history for investigation; do not remove shared collateral or registry history.

Transaction counts depend on the number of migrated legacy IDs/routes and caller restrictions. The earlier 15–19 estimate is not a deployment budget.

The mandatory [fork acceptance TODO](dcap-v2-fork-validation.md) expands the
deployment, raw/ZK verification, Rust/Go SDK and gas-breakdown acceptance matrix.
The user authorized that local fork/proof phase on 2026-09-12. Production
deployment and publication remain unexecuted and require separate approval.
