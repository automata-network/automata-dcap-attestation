# Compact V2 isolated test deployment coordinator

Implementation under regression. Do not use historical inline-body 2.1 IDs,
SP1 v5 ELFs or the previously deployed FeeV2 address with this revision.
SP1 6.8.0 integration and new guest/proof acceptance remain prerequisites for
enabling SP1 in `programs`. Empty `programs` means raw-only, ZK paused.

The coordinator discovers legacy Fee/Router addresses from `deployment/current`,
reads live DAO dependencies/P256/fees, and inventories versioned DAOs from the
registry (or an explicit reviewed `evaluations` array). It deploys six independent
contracts including a new Router, plus an optional independent SP1 v6 verifier;
shared Storage changes are additive reader
grants only. No shared helper switch, collateral writes, legacy ID migration or
`current` promotion occurs.

1. Commit the reviewed implementation. Copy `coordinator.example.json` to an
   operator-owned run directory and fill `owner`, `accounts` (address → Foundry
   keystore name), and any reviewed program records. No private keys in JSON.
2. Set `DCAP_RPC_URL` and `ETHERSCAN_API_KEY` in your shell. Keep the endpoint and
   keys out of version control. Ensure all required keystores/signers are available.
3. Run without broadcast first:

   ```bash
   node scripts/deploy-dcap-v2/deploy.mjs /absolute/config.json /absolute/run
   ```

   Inspect `plan.json`, `before.json`, `readers.json`, `pending-signers.json` and
   the deployment simulation. One actual owner is required per distinct resolver.
   Multisig/unknown owners block broadcast before deployment; arrange the external
   authorization workflow rather than substituting a deployer signer.
4. Execute the same command with `--broadcast`. It simulates each new stage,
   broadcasts, checkpoints deployment and configuration, waits for finalized
   receipts (returns `WAIT_FINALIZATION` if not yet final), verifies source, then
   publishes versioned registries. Rerun after finalization; completed stages are
   not resent. An interrupted broadcast requires review of Foundry receipts and
   `--resume`, which resumes that stage's original broadcast, not a fresh deployment.

   ```bash
   node scripts/deploy-dcap-v2/deploy.mjs /absolute/config.json /absolute/run --broadcast
   ```

Successful publication writes `deployment/v2.0/CHAIN`, and adds `PCKHelperV2` to
the PCCS submodule deployment file. It does not change `current`, old addresses,
or universal verifier submodule deployment files. A pre-existing v2.0 directory
must be explicitly reviewed/archived by the operator, never silently overwritten.
Source verification/readback success is **not** real-proof or release acceptance.

Program entries follow `publish-v2.mjs`: `backend` (1 RISC Zero, 2 SP1),
`minCheck`, native `id`, `verifier`, `proofSelector`, `buildSourceCommit`,
`artifactSha256`, `evidenceSha256`. Each enabled backend needs exactly one strict
default; SP1 also requires `buildSdkVersion: "6.8.0"` in its reviewed provenance.
Each backend may register one distinct minimal ID in addition to the strict
default. Both must use the reviewed
verifier; that verifier must support the new circuit/proof selector (in particular,
do not assume a v5-only SP1 verifier accepts v6). Pico is rejected for live rollout.

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
