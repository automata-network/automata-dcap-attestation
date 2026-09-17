# Isolated V2 testnet deployment

This is a separate deployment, not a shared-Router upgrade. It creates six
contracts: FeeV2, three quote verifiers, PCKHelperV2 and PCCSRouterV2. Existing
DAOs/storage/helpers and supported universal verifiers are reused. No live
deployment has been performed by adding these scripts.

## Prerequisites and inputs

- Complete the [current Docker guest handoff](../../docs/dcap-v2-current-build.md).
  Do not register historical pre-minCheck/Keccak IDs. Keep the exact returned
  program, native ID, artifact SHA-256, source commit and evidence archive hash.
- Prepare a private working copy of `hoodi-plan.example.json`. Its old addresses
  are historical registry entries, NOT a fresh confirmation of live state. The
  evaluation inventory must be read/reviewed; `[20,21]` is only an example.
- `sourceCommit` pins the **guest build source**. Preserve Foundry broadcast files
  and the deployment-script revision separately. The publisher checks deployed
  runtime against the locally compiled `evm/out` artifacts.
- `programs: []` is raw-only, with V2 ZK paused. To test ZK, add only backends
  already supported by the target's legacy Fee. Pico is not deployable here.
  Each entry has this shape (use real values, no placeholders):

```json
{
  "backend": 2,
  "id": "0x<new SP1 native vkey>",
  "proofSelector": "0x<actual proof selector>",
  "verifier": "0x<existing target-chain universal verifier>",
  "buildSourceCommit": "359def3bce58ba269c48373817f48b7144424f14",
  "artifactSha256": "<64 hex digits>",
  "evidenceSha256": "<64 hex digits>"
}
```

The build references are operator-reviewed provenance; the publisher does not
claim to verify a Docker evidence archive or a real proof from those references.
Keep RPC credentials in `DCAP_RPC_URL`, never in the plan/manifest. Use a keystore
signer, not a private key pasted into commands. Test owner and Storage owner may
be different; shared Storage authorization needs its actual owner.

## 1. Read-only preflight snapshot (repository root)

```sh
node scripts/deploy-dcap-v2/publish-v2.mjs snapshot /absolute/hoodi-plan.json /absolute/hoodi-before.json
```

Requires `DCAP_RPC_URL`, `cast`, Node with fetch, and RPC support for `finalized`
blocks. Reads the legacy owner, fees, verifier wiring, six Router dependencies,
selected versioned DAOs, backend IDs and universal runtimes. Refuses backend
expansion. No transactions or registry writes. The before snapshot must predate
deployment. It is not a complete non-enumerable proof-route inventory.

Legacy backend reads cover RISC Zero (1) and SP1 (2) only: the existing Hoodi Fee
rejects Pico enum value 3, including in its view getters. This is not an RPC
provider failure. New FeeV2 readback still checks Pico (3) to reject accidental
registration. Errors include the RPC method, and for contract calls the address,
function/arguments and pinned block, together with provider error details.
Endpoint URLs and embedded credentials are redacted. Do not bypass `finalized`
or treat a failed required RPC call as empty configuration. A snapshot failing
during RPC reads/validation does not create its output file; rerun the same
command after fixing the cause.

## 2. Simulate, review, then explicitly broadcast

From `evm/`, with these task-specific variables set to the reviewed plan values:

```sh
forge script forge-script/DeployDcapV2.s.sol:DeployDcapV2 \
  --rpc-url "$DCAP_RPC_URL" \
  --sig 'deployIsolated(uint256,address,address,address,address,uint32[])' \
  560048 "$DCAP_TEST_OWNER" "$DCAP_OLD_ROUTER" "$DCAP_OLD_FEE" "$DCAP_P256" '[20,21]'
```

Only after reviewing simulation, repeat with `--broadcast --account YOUR_KEYSTORE`.
For a multisig owner, use its approved execution workflow instead of pretending
the owner is an EOA. Preserve broadcast receipts. Copy all six addresses into
the plan and all deployment/configuration transaction hashes into `transactions`.
There is no registry write during simulation or broadcast.

This creates a restricted independent Router with the reviewed DAO mappings,
authorizes FeeV2 and V3/4/5, copies fee basis points and leaves ZK paused during
configuration. It calls no setter on old Fee/Router/DAOs. **Do not run
`switchHelper()` or the old `DeployRouter.run()` for this workflow.** The latter
writes `current`, which this workflow deliberately avoids.

## 3. Add read permission, not DAO/writer permission

Read `resolver()` for each selected TCB evaluation, PCS, PCK, QE identity and
FMSPC DAO. For each distinct resolver, invoke the following with one of its DAOs:

```sh
forge script forge-script/DeployDcapV2.s.sol:DeployDcapV2 \
  --rpc-url "$DCAP_RPC_URL" \
  --sig 'authorizeIsolatedReader(uint256,address,address,address,address)' \
  560048 "$DCAP_STORAGE_OWNER" "$DCAP_OLD_ROUTER" "$DCAP_NEW_ROUTER" "$DCAP_DAO"
```

Review, then broadcast with that Storage owner's signer. This only adds
`setCallerAuthorization(newRouter, true)` and is idempotent. It never calls
`grantDao`, changes restriction flags, modifies old reader entries, or upserts
collateral. The publisher requires the explicit grant even if reads are currently
open, so a later restoration of restrictions cannot silently break V2.

## 4. Configure ZK, then enable the isolated test instance

The existing `migrateLegacyBackend` stage can copy old IDs/defaults and an
explicit complete proof-selector inventory to the NEW Fee. Use it if legacy ZK
selectors on the new Fee are in scope; it never changes the old Fee. Inventory
freezes/overrides from events/config and preserve security freezes before enabling
V2, since routes are shared between selectors **within the new Fee instance**.
No complete route inventory is auto-discovered by the publisher.

For each supported backend, while paused:

```sh
forge script forge-script/DeployDcapV2.s.sol:DeployDcapV2 \
  --rpc-url "$DCAP_RPC_URL" \
  --sig 'configureV2Backend(address,address,uint8,bytes32,address)' \
  "$DCAP_TEST_OWNER" "$DCAP_NEW_FEE" 2 "$DCAP_NEW_SP1_ID" "$DCAP_SP1_VERIFIER"

forge script forge-script/DeployDcapV2.s.sol:DeployDcapV2 \
  --rpc-url "$DCAP_RPC_URL" \
  --sig 'enableIsolatedZk(uint256,address,address,address,address,uint8[])' \
  560048 "$DCAP_TEST_OWNER" "$DCAP_OLD_FEE" "$DCAP_OLD_ROUTER" "$DCAP_NEW_FEE" '[2]'
```

Again, these are simulations unless you explicitly append broadcast/signer flags.
The example selects SP1 only; don't infer Hoodi RISC Zero support from Sepolia.
Test ZK is enabled for on-chain testing, not held until production acceptance.
Use the new Docker program to generate/verify real EVM-compatible proofs; a core
proof, composite receipt, mock, or guest execution is not an on-chain proof.

## 5. Confirm live state and write registries

Wait for the transactions to be finalized. Build the exact deployment source
with the release/default Foundry profile (`forge build` from `evm/`). From root:

```sh
node scripts/deploy-dcap-v2/publish-v2.mjs publish \
  /absolute/hoodi-plan.json /absolute/hoodi-before.json /absolute/hoodi-readback.json
```

This uses read-only RPC and checks chain, successful finalized direct-deployment
receipts for all six addresses, compiled runtime/immutables, owner, quote versions,
P256, isolated Router/helper, selected DAO mappings, reader permissions, fees,
pause state and exact configured V2 ID inventory/proof routes. It rejects changes
to the snapshotted legacy configuration. A live legacy update may legitimately
require a reviewed new baseline; do not bypass a failed comparison.

Only after passing, it writes:

- `rust-crates/libraries/network-registry/deployment/v2.0/560048/dcap.json`:
  old keys preserved plus FeeV2, V3/4/5V2, **PCCSRouterV2**, PCKHelperV2.
- The same directory's `onchain_pccs.json`: reused addresses, the selected
  evaluation inventory and additive PCKHelperV2.
- `manifest.json` and the requested readback report, marked TEST_ONLY and not
  proof acceptance/release approval.
- `evm/lib/automata-on-chain-pccs/deployment/560048.json`: **only the additive
  PCKHelperV2 key**, preserving PCKHelper and all other existing keys. This dirties
  the PCCS submodule; review/commit/push it in that repository, then update the
  parent's gitlink separately. No automatic commit/push is performed.

No `current`/`v1.1` files are changed. Rust/Go SDKs explicitly choosing `v2.0`
require PCCSRouterV2 and never fall back to PCCSRouter. Rebuild the SDK to refresh
its compile-time embedded registry. Do not publish the test instance as a default.

The publisher refuses an existing chain output directory/report. For a deliberate
replacement, archive the previous V2 chain directory/report before retrying;
never erase its history or repoint old users. File writes across the parent and
submodule are not a single transaction; retain the readback report if disk/permission
failure interrupts publication and review the partial diff before retrying.

`sp1-contracts` and `risc0-ethereum` deployment registries describe their universal
verifiers, not this project's guest IDs. They need no edits when those verifiers
are reused. Record new guest IDs/proof selectors in the DCAP manifest/FeeV2 instead.

For eventual broad rollout, write verified deployments to `v2.0` first. Promotion
of corresponding `current` chain files is a separate explicitly approved release
step after acceptance; it is intentionally not performed by this test publisher.
Preserve frozen `v1.1` and all additive legacy keys when doing that promotion.

## Offline regression

```sh
node scripts/deploy-dcap-v2/publish-v2.test.mjs
cd evm
forge test --match-contract DeployDcapV2IsolatedTest
```

These test deployment isolation/configuration and mocked readback guards, not a
live Hoodi deployment, fresh Docker build, or real-proof acceptance.
