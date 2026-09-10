# DCAP V2 rollout (not executed)

## Implementation details

- Five new deployments: PCKHelperV2, V3/V4/V5QuoteVerifierV2, FeeV2. PCCS DAOs/storage, CRL/FMSPC helpers, P-256 and universal proof verifiers are reused.
- Canonical output serialization and V2 journal/collateral validation live in FeeV2 to meet EIP-170. Quote verifiers return an internal ABI envelope to FeeV2; that envelope is never an application output or journal.
- The shared Router must authorize FeeV2 as well as all three quote verifiers when caller restrictions are enabled.
- Legacy selectors retain the old parser, acceptance policy, output, events, and program family. V2 uses the strict identity parser and Rust production quote policy, including debug, TDX attribute and migration-service checks. V2 rejects trailing quote/authentication bytes.
- Legacy and V2 program IDs/defaults are independent. Universal proof-selector routes/security freezes are shared. V2 can be paused independently without touching old IDs/routes.
- Host V2 selection is explicit: use version v2.0 and DCAP_V2_ELF pointing to the backend-specific audited artifact. The artifact's native identifier must match the release manifest, not merely its ELF SHA-256.

## Gates and ordering

1. Review and commit the PCCS change in its own repository, then pin the DCAP submodule to that commit. The current workspace contains uncommitted submodule edits; no new commit/pin is claimed.
2. Finalize all three guest toolchains and lockfiles. Rebuild twice from pinned source; compare ELF hashes/native IDs. Prove real quotes and verify against the existing universal verifier contracts. Execution-only runs and mocked proof verifiers do not satisfy this gate.
3. Fill the release manifest from live state. Inventory every required legacy ID, including ATKJ compact programs, plus default IDs, proof-selector routes/freezes, fee basis points and all six Router components. Mapping routes require historical event/config inspection; do not assume the default verifier covers every route.
4. Simulate DeployDcapV2 stages on a fork of the target chain. Deploy five new contracts. Configure only FeeV2 and authorize the four new readers; copy legacy fee configuration, IDs and routes. Keep V2 ZK paused while staging.
5. Register separately audited V2 native IDs against reused universal verifiers. Re-read new configuration and compare the exact old/default ID sets and route states to the manifest.
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
