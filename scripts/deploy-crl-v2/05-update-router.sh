#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

init_deployment_context
forge_broadcast_args

PCCS_FILE="$(registry_pccs_file)"
DCAP_FILE="$(registry_dcap_file)"
PCCS_SOURCE_FILE="$PCCS_ROOT/deployment/$CHAIN_ID.json"
ROUTER_ADDRESS="$(json_address "$DCAP_FILE" PCCSRouter)"
PCS_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataPcsDaoV2)"
PCK_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataPckDaoV2)"
CRL_HELPER_ADDRESS="$(json_address "$PCCS_FILE" X509CRLHelperV2)"
TCB_EVAL_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataTcbEvalDaoCrlV2)"
TCB_EVALUATION_NUMBERS="${TCB_EVALUATION_NUMBERS:-20 21}"

keys=(X509CRLHelperV2 PccsDependencyConfig AutomataPcsDaoV2 AutomataPckDaoV2 AutomataTcbEvalDaoCrlV2)
for eval_number in $TCB_EVALUATION_NUMBERS; do
    keys+=(
        "AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${eval_number}"
        "AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${eval_number}"
    )
done
for key in "${keys[@]}"; do
    source_address="$(json_address "$PCCS_SOURCE_FILE" "$key")"
    registry_address="$(json_address "$PCCS_FILE" "$key")"
    assert_address_eq "$key registry value" "$registry_address" "$source_address"
done

require_contract_code PCCSRouter "$ROUTER_ADDRESS"
require_contract_code AutomataPcsDaoV2 "$PCS_DAO_ADDRESS"
require_contract_code AutomataPckDaoV2 "$PCK_DAO_ADDRESS"
require_contract_code X509CRLHelperV2 "$CRL_HELPER_ADDRESS"
require_contract_code AutomataTcbEvalDaoCrlV2 "$TCB_EVAL_DAO_ADDRESS"
require_exact_index_v2 "$CRL_HELPER_ADDRESS"

ROUTER_OWNER="$(cast call "$ROUTER_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
assert_address_eq "PCCSRouter owner" "$ROUTER_OWNER" "$OWNER_ADDRESS"

if [[ "${REQUIRE_INDEXED_CRLS:-true}" == "true" ]]; then
    info "Checking ROOT, PROCESSOR, and PLATFORM CRL indexes before the router switch"
    require_all_stored_crls_indexed "$PCCS_FILE"
fi

CURRENT_PCS="$(cast call "$ROUTER_ADDRESS" 'pcsDaoAddr()(address)' --rpc-url "$RPC_URL")"
CURRENT_PCK="$(cast call "$ROUTER_ADDRESS" 'pckDaoAddr()(address)' --rpc-url "$RPC_URL")"
CURRENT_CRL="$(cast call "$ROUTER_ADDRESS" 'crlHelperAddr()(address)' --rpc-url "$RPC_URL")"
CURRENT_TCB_EVAL="$(cast call "$ROUTER_ADDRESS" 'tcbEvalDaoAddr()(address)' --rpc-url "$RPC_URL")"

all_current=true
if [[ "${CURRENT_PCS,,}" != "${PCS_DAO_ADDRESS,,}" \
    || "${CURRENT_PCK,,}" != "${PCK_DAO_ADDRESS,,}" \
    || "${CURRENT_CRL,,}" != "${CRL_HELPER_ADDRESS,,}" \
    || "${CURRENT_TCB_EVAL,,}" != "${TCB_EVAL_DAO_ADDRESS,,}" ]]; then
    all_current=false
fi
for eval_number in $TCB_EVALUATION_NUMBERS; do
    expected_qe="$(json_address "$PCCS_FILE" "AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${eval_number}")"
    expected_fmspc="$(json_address "$PCCS_FILE" "AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${eval_number}")"
    current_qe="$(cast call "$ROUTER_ADDRESS" 'qeIdDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")"
    current_fmspc="$(cast call "$ROUTER_ADDRESS" 'fmspcTcbDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")"
    if [[ "${current_qe,,}" != "${expected_qe,,}" || "${current_fmspc,,}" != "${expected_fmspc,,}" ]]; then
        all_current=false
    fi
done

if [[ "$all_current" == "true" ]]; then
    success "PCCSRouter already uses the complete CRL V2 stack"
    exit 0
fi

run_router_update() {
    local signature="$1"
    shift
    (
        cd "$DCAP_ROOT/evm"
        OWNER="$OWNER_ADDRESS" forge script forge-script/DeployRouter.s.sol:DeployRouter \
            "${FORGE_BROADCAST_ARGS[@]}" \
            --sig "$signature" "$@"
    )
}

require_command forge
info "Building automata-dcap-attestation EVM contracts"
(cd "$DCAP_ROOT/evm" && forge build)

if [[ "${CURRENT_PCS,,}" == "${PCS_DAO_ADDRESS,,}" \
    && "${CURRENT_PCK,,}" == "${PCK_DAO_ADDRESS,,}" \
    && "${CURRENT_CRL,,}" == "${CRL_HELPER_ADDRESS,,}" ]]; then
    success "PCCSRouter core already uses CRL V2"
else
    info "Switching PCCSRouter CRL-sensitive core to V2"
    run_router_update 'updateCrlV2Config()'
fi

if [[ "${CURRENT_TCB_EVAL,,}" != "${TCB_EVAL_DAO_ADDRESS,,}" ]]; then
    info "Switching PCCSRouter TCB evaluation DAO to the configurable CRL V2 deployment"
    run_router_update 'updateCrlV2TcbEvalConfig()'
fi

for eval_number in $TCB_EVALUATION_NUMBERS; do
    expected_qe="$(json_address "$PCCS_FILE" "AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${eval_number}")"
    expected_fmspc="$(json_address "$PCCS_FILE" "AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${eval_number}")"
    current_qe="$(cast call "$ROUTER_ADDRESS" 'qeIdDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")"
    current_fmspc="$(cast call "$ROUTER_ADDRESS" 'fmspcTcbDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")"
    if [[ "${current_qe,,}" != "${expected_qe,,}" || "${current_fmspc,,}" != "${expected_fmspc,,}" ]]; then
        info "Switching PCCSRouter evaluation $eval_number Enclave Identity and FMSPC mappings"
        run_router_update 'updateCrlV2VersionedDaoConfig(uint32)' "$eval_number"
    fi
done

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
for eval_number in $TCB_EVALUATION_NUMBERS; do
    assert_address_eq \
        "PCCSRouter evaluation $eval_number Enclave Identity DAO" \
        "$(cast call "$ROUTER_ADDRESS" 'qeIdDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")" \
        "$(json_address "$PCCS_FILE" "AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${eval_number}")"
    assert_address_eq \
        "PCCSRouter evaluation $eval_number FMSPC DAO V2" \
        "$(cast call "$ROUTER_ADDRESS" 'fmspcTcbDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")" \
        "$(json_address "$PCCS_FILE" "AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${eval_number}")"
done

success "PCCSRouter now uses the complete configurable CRL V2 stack"
