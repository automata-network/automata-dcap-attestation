#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

init_deployment_context
forge_broadcast_args
load_attester_workers

DEPLOYMENT_FILE="$PCCS_ROOT/deployment/$CHAIN_ID.json"
TCB_EVALUATION_NUMBERS="${TCB_EVALUATION_NUMBERS:-20 21}"

DEPENDENCY_CONFIG_ADDRESS="$(json_address "$DEPLOYMENT_FILE" PccsDependencyConfig)"
PCS_DAO_ADDRESS="$(json_address "$DEPLOYMENT_FILE" AutomataPcsDaoV2)"
CRL_HELPER_ADDRESS="$(json_address "$DEPLOYMENT_FILE" X509CRLHelperV2)"
STORAGE_ADDRESS="$(json_address "$DEPLOYMENT_FILE" AutomataDaoStorage)"
STORAGE_V2_ADDRESS="$(json_address "$DEPLOYMENT_FILE" AutomataDaoStorageV2)"

require_contract_code PccsDependencyConfig "$DEPENDENCY_CONFIG_ADDRESS"
require_contract_code AutomataPcsDaoV2 "$PCS_DAO_ADDRESS"
require_contract_code X509CRLHelperV2 "$CRL_HELPER_ADDRESS"
require_contract_code AutomataDaoStorage "$STORAGE_ADDRESS"
require_contract_code AutomataDaoStorageV2 "$STORAGE_V2_ADDRESS"

run_deployment() {
    local signature="$1"
    shift
    local command=(
        forge script script/automata/versioned/DeployAutomataVersioned.s.sol:DeployAutomataVersioned
        "${FORGE_BROADCAST_ARGS[@]}"
        --sig "$signature"
        "$@"
    )
    if [[ "${RESUME:-false}" == "true" ]]; then
        command+=(--resume)
    fi
    (cd "$PCCS_ROOT" && OWNER="$OWNER_ADDRESS" "${command[@]}")
}

deploy_if_missing() {
    local key="$1"
    local signature="$2"
    shift 2

    if address="$(json_address_if_present "$DEPLOYMENT_FILE" "$key")"; then
        require_contract_code "$key" "$address"
        success "$key already deployed at $address"
        return
    fi

    info "Deploying $key"
    run_deployment "$signature" "$@"
    address="$(json_address "$DEPLOYMENT_FILE" "$key")"
    require_contract_code "$key" "$address"
    success "$key deployed at $address"
}

require_dynamic_dependencies() {
    local label="$1"
    local dao="$2"
    assert_address_eq \
        "$label PCS DAO" \
        "$(cast call "$dao" 'Pcs()(address)' --rpc-url "$RPC_URL")" \
        "$PCS_DAO_ADDRESS"
    assert_address_eq \
        "$label CRL helper" \
        "$(cast call "$dao" 'crlLibAddr()(address)' --rpc-url "$RPC_URL")" \
        "$CRL_HELPER_ADDRESS"
}

require_command forge
info "Building configurable PCCS DAOs"
(cd "$PCCS_ROOT" && forge build)

deploy_if_missing AutomataTcbEvalDaoCrlV2 'deployTcbEvalDao()'
TCB_EVAL_DAO_ADDRESS="$(json_address "$DEPLOYMENT_FILE" AutomataTcbEvalDaoCrlV2)"
assert_address_eq \
    "AutomataTcbEvalDaoCrlV2 owner" \
    "$(cast call "$TCB_EVAL_DAO_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")" \
    "$OWNER_ADDRESS"
assert_address_eq \
    "AutomataTcbEvalDaoCrlV2 resolver" \
    "$(cast call "$TCB_EVAL_DAO_ADDRESS" 'resolver()(address)' --rpc-url "$RPC_URL")" \
    "$STORAGE_ADDRESS"
require_dynamic_dependencies AutomataTcbEvalDaoCrlV2 "$TCB_EVAL_DAO_ADDRESS"
require_storage_writer AutomataTcbEvalDaoCrlV2 "$STORAGE_ADDRESS" "$TCB_EVAL_DAO_ADDRESS"
grant_attester_roles AutomataTcbEvalDaoCrlV2 "$TCB_EVAL_DAO_ADDRESS"

for eval_number in $TCB_EVALUATION_NUMBERS; do
    [[ "$eval_number" =~ ^[1-9][0-9]*$ ]] || die "Invalid TCB evaluation number: $eval_number"

    enclave_key="AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${eval_number}"
    fmspc_key="AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${eval_number}"

    deploy_if_missing "$enclave_key" 'deployEnclaveIdDaoVersioned(uint32)' "$eval_number"
    deploy_if_missing "$fmspc_key" 'deployFmspcTcbDaoVersionedV2(uint32)' "$eval_number"

    enclave_address="$(json_address "$DEPLOYMENT_FILE" "$enclave_key")"
    fmspc_address="$(json_address "$DEPLOYMENT_FILE" "$fmspc_key")"

    assert_address_eq \
        "$enclave_key owner" \
        "$(cast call "$enclave_address" 'owner()(address)' --rpc-url "$RPC_URL")" \
        "$OWNER_ADDRESS"
    assert_address_eq \
        "$enclave_key resolver" \
        "$(cast call "$enclave_address" 'resolver()(address)' --rpc-url "$RPC_URL")" \
        "$STORAGE_ADDRESS"
    [[ "$(cast call "$enclave_address" 'TCB_EVALUATION_NUMBER()(uint32)' --rpc-url "$RPC_URL")" == "$eval_number" ]] \
        || die "$enclave_key evaluation number mismatch"
    require_dynamic_dependencies "$enclave_key" "$enclave_address"
    require_storage_writer "$enclave_key" "$STORAGE_ADDRESS" "$enclave_address"
    grant_attester_roles "$enclave_key" "$enclave_address"

    assert_address_eq \
        "$fmspc_key owner" \
        "$(cast call "$fmspc_address" 'owner()(address)' --rpc-url "$RPC_URL")" \
        "$OWNER_ADDRESS"
    assert_address_eq \
        "$fmspc_key resolver" \
        "$(cast call "$fmspc_address" 'resolver()(address)' --rpc-url "$RPC_URL")" \
        "$STORAGE_V2_ADDRESS"
    [[ "$(cast call "$fmspc_address" 'TCB_EVALUATION_NUMBER()(uint32)' --rpc-url "$RPC_URL")" == "$eval_number" ]] \
        || die "$fmspc_key evaluation number mismatch"
    require_dynamic_dependencies "$fmspc_key" "$fmspc_address"
    require_storage_writer "$fmspc_key" "$STORAGE_V2_ADDRESS" "$fmspc_address"
    grant_attester_roles "$fmspc_key" "$fmspc_address"
done

success "CRL V2-dependent TCB evaluation 20/21 DAOs are deployed, authorized for ${#ATTESTER_WORKERS[@]} worker(s), and dynamically bound"
