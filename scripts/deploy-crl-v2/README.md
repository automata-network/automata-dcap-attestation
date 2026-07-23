# CRL V2 contract rollout

These scripts upgrade the CRL-sensitive PCCS path without changing the existing
shared storage or replacing the attestation entrypoint. Every transaction is
signed with an encrypted Foundry keystore; `PRIVATE_KEY` is deliberately
rejected.

## Configuration

If the deployer key has not been imported yet, create an encrypted Foundry
keystore through the interactive prompt (the private key is not placed in shell
history):

```bash
cast wallet import dcap-crl-v2-deployer --interactive
```

Create a deployment environment file outside the repository:

```bash
cp scripts/deploy-crl-v2/deployment.env.example /secure/path/crl-v2-1315.env
chmod 600 /secure/path/crl-v2-1315.env
```

Fill in `RPC_URL`, `CHAIN_ID`, and `KEYSTORE_PATH`. For an interactive rollout,
omit `KEYSTORE_PASSWORD_FILE`; `run-all.sh` prompts once and uses a temporary
mode-0600 password file that is deleted on exit.

`run-all.sh` assumes the same keystore address owns `AutomataDaoStorage`,
`AutomataDaoStorageV2`, and `PCCSRouter`, and becomes owner of the new DAOs.
Set `ATTESTER_ADDRESSES` to one or more QPL/dashboard workers that submit
collateral. Both space- and comma-separated lists are accepted:

```bash
ATTESTER_ADDRESSES="0xStagingWorker 0xProductionWorker"
```

Stage 3 grants every listed worker `ATTESTER_ROLE` on every newly deployed TCB
evaluation, Enclave Identity, and FMSPC DAO. Stages 6 and 8 verify that every
worker still has the role. Duplicate addresses are ignored; malformed and zero
addresses stop the rollout. The legacy singular `ATTESTER_ADDRESS` remains
accepted for existing single-worker deployment files, but
`ATTESTER_ADDRESSES` takes precedence when both variables are set.

Load the configuration:

```bash
set -a
source /secure/path/crl-v2-1315.env
set +a
```

## Complete rollout

```bash
./scripts/deploy-crl-v2/run-all.sh
```

The runner stops immediately if any stage fails. Re-running it is safe:
completed CRL indexes and an already-updated router are detected and skipped.
It deliberately does **not** revoke the legacy PCS DAO.

## Independent stages

```bash
./scripts/deploy-crl-v2/01-deploy-pccs-v2.sh
./scripts/deploy-crl-v2/02-index-stored-crls.sh
./scripts/deploy-crl-v2/03-deploy-dependent-daos.sh
./scripts/deploy-crl-v2/04-sync-deployment.sh
./scripts/deploy-crl-v2/05-update-router.sh
./scripts/deploy-crl-v2/06-verify.sh
```

The stages are intentionally ordered as follows:

1. Deploy `X509CRLHelperV2`, the shared `PccsDependencyConfig`,
   `AutomataPcsDaoV2`, and `AutomataPckDaoV2`; initialize the dependency pair;
   grant storage access; and authorize the V2 PCS DAO as an indexer.
2. Migrate the ROOT, PROCESSOR, and PLATFORM CRLs that were already stored by
   V1. Each CRL is validated and indexed atomically in one transaction.
3. Deploy the configurable `AutomataTcbEvalDao`, evaluation 20/21
   `AutomataEnclaveIdentityDaoVersioned`, and evaluation 20/21
   `AutomataFmspcTcbDaoVersionedV2`; authorize storage and every configured
   collateral worker. The legacy non-V2 FMSPC implementation is not deployed.
4. Copy all new addresses into the DCAP network registry under distinct
   `CrlV2` keys, preserving legacy addresses.
5. Switch the Router core, TCB evaluation DAO, and evaluation 20/21 mappings.
6. Verify code, dynamic PCS/CRL bindings, storage permissions, worker roles,
   indexes, registry values, Router getters, and that legacy PCS is still
   authorized.

The existing Router stays functional throughout stages 1-4. During stage 5,
each Router transaction points either to a complete legacy component or a
complete new component; the shared storage and stable collateral keys keep
reads available. Legacy PCS stays authorized so evaluation 19 can continue
through its last valid collateral window.

Every new CRL-aware DAO resolves one atomic `(PCS DAO, CRL helper)` pair from
`PccsDependencyConfig`. The initial pair is set before Router activation.
Subsequent owner-scheduled changes emit an event, wait exactly three hours,
and may then be executed by any caller. The old pair remains active during the
delay; the owner can cancel the pending pair.

The migration stage is only for pre-existing V1 collateral. After the Router
switch, every successful V2 CRL upsert parses, authenticates, stores, and
completes its exact index in the same transaction. Reissues with the same
strictly parsed ordered serial set reuse the existing index even if validity,
revocation dates, entry metadata, or the signature changes.

If a Foundry deployment broadcast stopped after only some transactions were
submitted, resume stage 1 with:

```bash
RESUME=true ./scripts/deploy-crl-v2/01-deploy-pccs-v2.sh
```

To migrate only selected stored CRLs:

```bash
CA_LIST='processor platform' \
  ./scripts/deploy-crl-v2/02-index-stored-crls.sh
```

Rollback must first re-grant the legacy `AutomataPcsDao` with
`AutomataDaoStorage.grantDao`, then atomically restore the Router's V1 PCS/PCK/
CRL-helper addresses. Do not switch the Router back while its PCS DAO lacks
storage writer authorization.

## Retire evaluation 19 and revoke V1

After evaluation 19's last collateral has expired, run the destructive phase
separately. The script refuses to proceed if the chain is earlier than
`LEGACY_REVOKE_NOT_BEFORE`, if either SGX or TDX selects an evaluation below
20, or if the explicit confirmation flag is absent. It removes evaluation 19
from both Router mappings before revoking V1, validates every active DAO's
dynamic PCS binding, and re-indexes the current CRLs after revocation.

```bash
export LEGACY_REVOKE_NOT_BEFORE=1789257600 # 2026-09-13 00:00:00 UTC
export CONFIRM_LEGACY_PCS_REVOKE=true
./scripts/deploy-crl-v2/07-revoke-legacy-pcs.sh
./scripts/deploy-crl-v2/08-verify-post-revoke.sh
```
