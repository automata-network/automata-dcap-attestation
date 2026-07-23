#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

init_deployment_context
forge_broadcast_args

[[ "${CONFIRM_LEGACY_PCS_REVOKE:-false}" == "true" ]] \
    || die "Set CONFIRM_LEGACY_PCS_REVOKE=true only after evaluation 19 collateral has expired"
[[ -n "${LEGACY_REVOKE_NOT_BEFORE:-}" && "$LEGACY_REVOKE_NOT_BEFORE" =~ ^[0-9]+$ ]] \
    || die "LEGACY_REVOKE_NOT_BEFORE must be the approved Unix timestamp for retiring evaluation 19"
RETIRED_TCB_EVALUATION_NUMBER="${RETIRED_TCB_EVALUATION_NUMBER:-19}"
MIN_ACTIVE_TCB_EVALUATION="${MIN_ACTIVE_TCB_EVALUATION:-20}"
TCB_EVALUATION_NUMBERS="${TCB_EVALUATION_NUMBERS:-20 21}"

PCCS_FILE="$(registry_pccs_file)"
DCAP_FILE="$(registry_dcap_file)"
ROUTER_ADDRESS="$(json_address "$DCAP_FILE" PCCSRouter)"
STORAGE_ADDRESS="$(json_address "$PCCS_FILE" AutomataDaoStorage)"
LEGACY_PCS_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataPcsDao)"
PCS_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataPcsDaoV2)"
PCK_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataPckDaoV2)"
CRL_HELPER_ADDRESS="$(json_address "$PCCS_FILE" X509CRLHelperV2)"
TCB_EVAL_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataTcbEvalDaoCrlV2)"

require_contract_code PCCSRouter "$ROUTER_ADDRESS"
require_contract_code AutomataDaoStorage "$STORAGE_ADDRESS"
require_contract_code AutomataPcsDao "$LEGACY_PCS_DAO_ADDRESS"

block_timestamp="$(cast block latest --field timestamp --rpc-url "$RPC_URL")"
block_timestamp="$(cast to-dec "$block_timestamp")"
(( block_timestamp >= LEGACY_REVOKE_NOT_BEFORE )) \
    || die "Chain time $block_timestamp is earlier than approved legacy revoke time $LEGACY_REVOKE_NOT_BEFORE"

# Revoking AutomataPcsDao also removes its ability to read storage, so only do
# this after the Router has atomically switched every CRL-sensitive component.
assert_address_eq \
    "PCCSRouter PCS DAO" \
    "$(cast call "$ROUTER_ADDRESS" 'pcsDaoAddr()(address)' --rpc-url "$RPC_URL")" \
    "$PCS_DAO_ADDRESS"
assert_address_eq \
    "PCCSRouter PCK DAO" \
    "$(cast call "$ROUTER_ADDRESS" 'pckDaoAddr()(address)' --rpc-url "$RPC_URL")" \
    "$PCK_DAO_ADDRESS"
assert_address_eq \
    "PCCSRouter CRL helper" \
    "$(cast call "$ROUTER_ADDRESS" 'crlHelperAddr()(address)' --rpc-url "$RPC_URL")" \
    "$CRL_HELPER_ADDRESS"
assert_address_eq \
    "PCCSRouter TCB evaluation DAO" \
    "$(cast call "$ROUTER_ADDRESS" 'tcbEvalDaoAddr()(address)' --rpc-url "$RPC_URL")" \
    "$TCB_EVAL_DAO_ADDRESS"

ACTIVE_DEPENDENT_DAOS="$TCB_EVAL_DAO_ADDRESS"
for eval_number in $TCB_EVALUATION_NUMBERS; do
    expected_qe="$(json_address "$PCCS_FILE" "AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${eval_number}")"
    expected_fmspc="$(json_address "$PCCS_FILE" "AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${eval_number}")"
    assert_address_eq \
        "PCCSRouter evaluation $eval_number Enclave Identity DAO" \
        "$(cast call "$ROUTER_ADDRESS" 'qeIdDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")" \
        "$expected_qe"
    assert_address_eq \
        "PCCSRouter evaluation $eval_number FMSPC DAO" \
        "$(cast call "$ROUTER_ADDRESS" 'fmspcTcbDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")" \
        "$expected_fmspc"
    ACTIVE_DEPENDENT_DAOS+=" $expected_qe $expected_fmspc"
done
export ACTIVE_DEPENDENT_DAOS

for tcb_id in 0 1; do
    active_eval="$(
        cast call "$ROUTER_ADDRESS" \
            'getStandardTcbEvaluationDataNumber(uint8)(uint32)' "$tcb_id" \
            --rpc-url "$RPC_URL"
    )" || die "Current TCB evaluation collateral is missing or expired for TCB id $tcb_id"
    (( active_eval >= MIN_ACTIVE_TCB_EVALUATION )) \
        || die "TCB id $tcb_id still selects evaluation $active_eval; expected at least $MIN_ACTIVE_TCB_EVALUATION"
done

zero_address="0x0000000000000000000000000000000000000000"
retired_qe="$(
    cast call "$ROUTER_ADDRESS" \
        'qeIdDaoVersionedAddr(uint32)(address)' "$RETIRED_TCB_EVALUATION_NUMBER" \
        --rpc-url "$RPC_URL"
)"
retired_fmspc="$(
    cast call "$ROUTER_ADDRESS" \
        'fmspcTcbDaoVersionedAddr(uint32)(address)' "$RETIRED_TCB_EVALUATION_NUMBER" \
        --rpc-url "$RPC_URL"
)"
if [[ "${retired_qe,,}" != "$zero_address" || "${retired_fmspc,,}" != "$zero_address" ]]; then
    info "Retiring evaluation $RETIRED_TCB_EVALUATION_NUMBER from both PCCSRouter mappings"
    (
        cd "$DCAP_ROOT/evm"
        OWNER="$OWNER_ADDRESS" forge script forge-script/DeployRouter.s.sol:DeployRouter \
            "${FORGE_BROADCAST_ARGS[@]}" \
            --sig 'retireVersionedDaoConfig(uint32)' "$RETIRED_TCB_EVALUATION_NUMBER"
    )
fi
assert_address_eq \
    "retired evaluation Enclave Identity mapping" \
    "$(cast call "$ROUTER_ADDRESS" 'qeIdDaoVersionedAddr(uint32)(address)' "$RETIRED_TCB_EVALUATION_NUMBER" --rpc-url "$RPC_URL")" \
    "$zero_address"
assert_address_eq \
    "retired evaluation FMSPC mapping" \
    "$(cast call "$ROUTER_ADDRESS" 'fmspcTcbDaoVersionedAddr(uint32)(address)' "$RETIRED_TCB_EVALUATION_NUMBER" --rpc-url "$RPC_URL")" \
    "$zero_address"

CONFIRM_LEGACY_PCS_REVOKE=true "$PCCS_ROOT/script/crl-v2/revoke-legacy-pcs-writer.sh"

# A valid Intel CRL can be submitted through V1 in the short interval between
# the Router switch and revocation. Once V1 is revoked the stored DER is stable;
# re-reading and indexing all three CAs repairs that race deterministically.
info "Reconciling current ROOT, PROCESSOR, and PLATFORM CRL indexes after legacy revocation"
"$PCCS_ROOT/script/crl-v2/index-stored-crls.sh"

require_storage_writer_revoked AutomataPcsDao "$STORAGE_ADDRESS" "$LEGACY_PCS_DAO_ADDRESS"
require_all_stored_crls_indexed "$PCCS_FILE"
success "Legacy PCS writer is revoked and every current CRL is indexed"
