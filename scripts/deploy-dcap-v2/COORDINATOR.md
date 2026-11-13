# V2 deployment coordinator: first deployment or entrypoint replacement

Implementation under regression. Do not use historical inline-body 2.1 IDs,
SP1 v5 ELFs or the previously deployed FeeV2 address with this revision.
SP1 6.8.0 integration and new guest/proof acceptance remain prerequisites for
enabling SP1 in `programs` for a first deployment. Empty `programs` means raw-only,
ZK paused, in `full` mode only. Publication is TEST_ONLY; neither mode promotes `current`.

| Mode | Source | Creates | Shared writes |
| --- | --- | --- | --- |
| `full` (default) | `deployment/current/CHAIN`, live V1.1 | Entry + Router + PCKHelper + V3/V4/V5; optional SP1 verifier | Storage reader grants for new Router |
| `replace-entrypoint` | `deployment/v2.0/CHAIN`, live V2 | **Only AutomataDcapAttestationV2** | Existing Router authorizes new entrypoint |

Use `full` for networks without PPID/PIID V2. Hoodi already has V2 and uses
`replace-entrypoint`. Shared PCCS DAOs/storage are retained in both modes. Existing
CRL/FMSPC helpers and P-256 are reused; cryptographic verifier addresses are separately
reviewed. No collateral upsert, helper switch, old permission removal, or live transaction
occurs implicitly. Pico is local-only.

## Hoodi: replace the entrypoint only

Copy `replace-entrypoint.example.json` to an operator directory **outside the repository**.
Fill `owner`, the actual Router owner's keystore, and two repaired RISC Zero build records.
Do not put SP1 records in `programs`: the coordinator discovers and preserves **all live
SP1 IDs**, their immutable modes, current strict default, default verifier, and every
explicit route/freeze, including nondefault routes. It requires the reviewed SP1 v6
verifier runtime. No SP1 guest rebuild or new verifier deployment is requested.

The original V2 manifest identifies the source entrypoint and its creation receipt.
The coordinator reads finalized state and scans route events from that creation block,
then cross-checks every route. RPC range limits are handled by smaller contiguous ranges;
unrelated RPC errors fail closed. The Router owner, fees, helper and quote verifier addresses
come from live state, not stale JSON. Reused runtime hashes and old reader permissions are
pinned in `before.json`; unexpected source changes block continuation/publication.

**Observed Hoodi inventory on 2026-11-13:** six SP1 IDs, whereas the original manifest
contains two. The current default is not the first registered strict ID. Owner and helper
also differ from that historical manifest. Never migrate only its two original records.
Known SP1 build provenance is retained byte-for-byte. IDs without a build record retain
their on-chain identity/mode and are listed in
`inherited-sp1-without-build-provenance.json`; no SDK version, ELF hash or new build claim
is invented. Review these inherited permissions before approving broadcast.

Run the same commands shown below with this config. Replacement stages are:

1. Snapshot/read-only preflight; check deployer and Router owner signers.
2. Deploy one paused entrypoint; copy existing V3/V4/V5 addresses and fee BP.
3. Authorize that new entrypoint on the existing Router. Do not touch Storage grants.
4. Migrate all live SP1 configuration; register repaired RISC Zero strict/minimal IDs
   and its explicit proof route. No old RISC Zero program/route is migrated.
5. Enable ZK on the test instance; wait for finality; verify source and read back configuration.
6. Archive the complete previous registry under `deployment/history/CHAIN/OLD_ENTRYPOINT/`
   and publish the replacement under `v2.0/CHAIN`. Reused addresses are synchronized from
   the snapshot (including a helper upgraded since the old manifest). The PCCS submodule,
   `current`, V1.1, and universal-verifier deployment files are not written in this mode.

Keep the existing `v2.0/CHAIN` directory in place until publication; **do not manually
archive it for replacement**. The coordinator checks its file hashes before broadcasting.
A source ZK pause, unknown runtime, missing owner, or source/provenance mode conflict stops
the run. Publication is not proof acceptance: run raw + SP1 + RISC Zero positive/negative
checks against the new address before application migration. Rollback keeps applications
on the previous address; do not revive an unsafe RISC Zero route.

## Other networks: first full V2 deployment

The coordinator discovers legacy Fee/Router addresses from `deployment/current`,
reads live DAO dependencies/P256/fees, and inventories versioned DAOs from the
registry (or an explicit reviewed `evaluations` array). It deploys six independent
contracts including a new Router, plus an optional independent SP1 v6 verifier;
shared Storage changes are additive reader
grants only. No shared helper switch, collateral writes, legacy ID migration or
`current` promotion occurs.

`deployment/v2.0/CHAIN` must not already exist. If V2 is already deployed, use
the replacement mode above instead of deleting its registry to bypass this guard.
Copy `coordinator.example.json` (`mode: "full"`) to an
operator-owned run directory and fill `owner`, `accounts` (address → Foundry
keystore name), and any reviewed program records. No private keys in JSON.

## Run either mode

Commit the implementation first and pin guest provenance before broadcast. Keep
run directories and large local evidence outside the checkout; the coordinator refuses
uncommitted/untracked implementation files. If only deployment tooling changed after a
guest build, preserve its original `buildSourceCommit`: the coordinator permits an
ancestor only after checking that Rust source/locks and proving scripts are unchanged
(deployment registry records are excluded). Otherwise it requires new reviewed artifacts.
Never relabel an old ELF's source commit to pass validation. Inherited SP1 IDs are separately
recorded as existing on-chain permissions, not newly built/reviewed programs.

1. Set `DCAP_RPC_URL` and `ETHERSCAN_API_KEY` in your shell. Keep the endpoint and
   keys out of version control. Ensure all required keystores/signers are available.
2. Run without broadcast first:

   ```bash
   node scripts/deploy-dcap-v2/deploy.mjs /absolute/config.json /absolute/run
   ```

   Inspect `plan.json`, `before.json`, `readers.json`, `pending-signers.json` and
   the deployment simulation. The dry run simulates contract creation/configuration in
   the deployment stage, not the later real-proof acceptance. In full mode one actual
   owner is required per distinct resolver; replacement needs the actual Router owner.
   Multisig/unknown owners block broadcast before deployment; arrange the external
   authorization workflow rather than substituting a deployer signer.
3. Execute the same command with `--broadcast`. It simulates each new stage,
   broadcasts, checkpoints deployment and configuration, waits for finalized
   receipts (returns `WAIT_FINALIZATION` if not yet final), verifies source, then
   publishes versioned registries. Rerun after finalization; completed stages are
   not resent. An interrupted broadcast requires review of Foundry receipts and
   `--resume`, which resumes that stage's original broadcast, not a fresh deployment.

   ```bash
   node scripts/deploy-dcap-v2/deploy.mjs /absolute/config.json /absolute/run --broadcast
   ```

In full mode, successful publication writes `deployment/v2.0/CHAIN`, and adds `PCKHelperV2` to
the PCCS submodule deployment file. It does not change `current`, old addresses,
or universal verifier submodule deployment files. A pre-existing v2.0 directory
is refused in full mode; replacement preserves it in the historical archive.
Source verification/readback success is **not** real-proof or release acceptance.

Source verification and runtime readback use the active `forge config --json`
artifact directory, including `FOUNDRY_PROFILE` / `FOUNDRY_OUT` overrides. Keep
the same Foundry settings when resuming a deployment.

### Resume after a Foundry array parser failure

Foundry expects `[0xe71e6620,0x4388a21c]`, not JSON-quoted hex elements.
The coordinator formats all script array arguments consistently, including nonempty
SP1 routes, backend selectors and evaluation numbers.

If `configureMinimalProgram` succeeded but the following `enable-zk` simulation
failed to parse its array, preserve the same config and run directory. Inspect
`state.json`: the completed backend stages should be present, `enable-zk` absent,
and `running` unset. Commit/sync this tooling repair, then rerun the original
`--broadcast` command without `--resume`; only the remaining stages execute.
If `running` is set, inspect the original broadcast receipts before using `--resume`.

A checkpoint may continue on a descendant commit only when every committed change
since its source pin is inside `scripts/deploy-dcap-v2/`. Contract sources, Foundry
settings, submodules, Rust/build inputs and registry files must remain unchanged.
The original `state.commit`, plan/snapshot `sourceCommit` and guest provenance remain
intact; `state.coordinatorCommit` and the final manifest record the repaired tooling
commit separately. A clean checkout is still required. Never edit checkpoint hashes,
delete a completed stage, or create a fresh run to bypass an interrupted deployment.

Program entries follow `publish-v2.mjs`: `backend` (1 RISC Zero, 2 SP1),
`minCheck`, native `id`, `verifier`, `proofSelector`, `buildSourceCommit`,
`artifactSha256`, `evidenceSha256`. New builds require the pinned deployment commit or
an ancestor with unchanged Rust/proving inputs. Each newly enabled backend needs exactly one strict
default; SP1 requires `buildSdkVersion: "6.8.0"`, and RISC Zero requires
`buildSdkVersion: "3.1.0"` with `proofSelector: "0xe71e6620"` in its reviewed provenance.
Each backend may register one distinct minimal ID in addition to the strict
default. Both must use the reviewed
verifier and proof selector; that verifier must support the new circuit/proof selector (in particular,
do not assume a v5-only SP1 verifier accepts v6). Pico is rejected for live rollout.
The first-deployment Foundry configuration/enable stages take selectors from this plan rather than
embedding a circuit selector. Legacy backend enablement is not a prerequisite:
disabled Sepolia RISC Zero stays disabled, and Hoodi can explicitly enable its
first V2 RISC Zero route. Legacy configuration is still snapshotted and compared
before publication. Never re-enable a vulnerable legacy backend to pass deployment.

For the optional seventh contract, set `deploySp1Groth16V6: true`, omit `verifier`
on both SP1 program entries, and use `proofSelector: "0x4388a21c"`. The coordinator
deploys `SP1Groth16VerifierV6`, resolves the address before configuration, verifies
its source/runtime and records it in the V2 `dcap.json`. The placeholder
`DEPLOY_SP1_GROTH16_V6_1` is allowed only for the pre-deployment snapshot, never
for publication. Supplying a verifier address and requesting a new one together
is rejected. This option supports Groth16 only; it does not add a shared gateway
route or rewrite the upstream verifier deployment registry.

The pinned SDK is 6.8.0; its circuit is **v6.1.0**, not v6.8.0. The official
verifier sources are from `sp1-contracts` tag v6.1.0, commit
`2ac5ecbbe473421a963d67e55f182e9a36576f7c`. Foundry compiles that isolated unit
with upstream-required Solidity 0.8.20, and all DCAP units with 0.8.27. Do not
override the whole project with `--use`/`FOUNDRY_SOLC_VERSION`. Proof calldata is
356 bytes (selector + exit code + recursion root + nonce + eight proof words),
not the historical 260-byte v5 encoding. Build/encoding checks are not evidence
that a newly generated proof has been accepted.

A source/config mismatch or interrupted/partial publication fails closed. Preserve
the run directory and resolve it before restarting; never delete checkpoints just
to bypass a failed check. A stale `coordinator.lock` after a killed process should
only be removed after confirming no coordinator or broadcast is still running.

## Regression checks

```bash
node --test scripts/deploy-dcap-v2/deploy.test.mjs \
  scripts/deploy-dcap-v2/publish-v2.test.mjs \
  scripts/deploy-dcap-v2/replacement.test.mjs
(cd evm && forge test --match-contract 'DeployDcapV2(Isolated|Replacement)Test|RolloutV2Test')
```

For read-only live inventory, set `DCAP_REPLACEMENT_RPC`, `DCAP_REPLACEMENT_CHAIN`,
and optionally `DCAP_REPLACEMENT_BLOCK`, then run `node scripts/deploy-dcap-v2/replacement.test.mjs`.
The local fork acceptance additionally requires `DCAP_REPLACEMENT_SOURCE`,
`DCAP_REPLACEMENT_RISC0_VERIFIER`, `DCAP_REPLACEMENT_RISC0_STRICT_ID`, and
`DCAP_REPLACEMENT_RISC0_MINIMAL_ID`. Run `forge test --match-contract DeployDcapV2ReplacementForkTest -vv`
from `evm`. For sources with explicit SP1 routes, pass `DCAP_REPLACEMENT_SP1_ROUTES`
as ABI-encoded `(bytes4[],address[])` from the preflight inventory (frozen targets
use the contract's `0xdead` sentinel). The Hoodi source at block **4005368** has no
explicit routes/freezes and uses its SP1 default verifier; empty arrays are correct there.

Validated on 2026-11-13: the live Hoodi snapshot and entrypoint-replacement fork at
4005368, including all six SP1 IDs and the non-first strict default. Unit tests also
cover active nondefault routes, permanent freezes, wrong owner/chain, source drift,
source pause, missing authorization, changed build inputs, registry collisions,
RPC event ABI/range limits, and old RISC Zero route rejection. This round sends no
public transactions and does not regenerate proofs. Live source-verification/publication
still occurs only during the operator-approved broadcast workflow.

The historical `sp1-core-handoff.test.mjs` suite is unrelated to this coordinator:
its two old success-path tests still expect the deliberately disabled SP1 v5 runner
to execute. It is not part of the passing deployment regression set above.
