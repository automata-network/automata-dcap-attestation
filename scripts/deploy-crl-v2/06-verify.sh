#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

init_network
load_attester_workers

PCCS_SOURCE_FILE="$PCCS_ROOT/deployment/$CHAIN_ID.json"
PCCS_FILE="$(registry_pccs_file)"
DCAP_FILE="$(registry_dcap_file)"

STORAGE_ADDRESS="$(json_address "$PCCS_FILE" AutomataDaoStorage)"
PCK_HELPER_ADDRESS="$(json_address "$PCCS_FILE" PCKHelper)"
LEGACY_PCS_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataPcsDao)"
CRL_HELPER_ADDRESS="$(json_address "$PCCS_FILE" X509CRLHelperV2)"
DEPENDENCY_CONFIG_ADDRESS="$(json_address "$PCCS_FILE" PccsDependencyConfig)"
PCS_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataPcsDaoV2)"
PCK_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataPckDaoV2)"
TCB_EVAL_DAO_ADDRESS="$(json_address "$PCCS_FILE" AutomataTcbEvalDaoCrlV2)"
ROUTER_ADDRESS="$(json_address "$DCAP_FILE" PCCSRouter)"
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

require_contract_code AutomataDaoStorage "$STORAGE_ADDRESS"
require_contract_code PCKHelper "$PCK_HELPER_ADDRESS"
require_contract_code AutomataPcsDao "$LEGACY_PCS_DAO_ADDRESS"
require_contract_code X509CRLHelperV2 "$CRL_HELPER_ADDRESS"
require_contract_code PccsDependencyConfig "$DEPENDENCY_CONFIG_ADDRESS"
require_contract_code AutomataPcsDaoV2 "$PCS_DAO_ADDRESS"
require_contract_code AutomataPckDaoV2 "$PCK_DAO_ADDRESS"
require_contract_code AutomataTcbEvalDaoCrlV2 "$TCB_EVAL_DAO_ADDRESS"
require_contract_code PCCSRouter "$ROUTER_ADDRESS"
require_exact_index_v2 "$CRL_HELPER_ADDRESS"

assert_address_eq \
    "PccsDependencyConfig PCS DAO" \
    "$(cast call "$DEPENDENCY_CONFIG_ADDRESS" 'pcsDao()(address)' --rpc-url "$RPC_URL")" \
    "$PCS_DAO_ADDRESS"
assert_address_eq \
    "PccsDependencyConfig CRL helper" \
    "$(cast call "$DEPENDENCY_CONFIG_ADDRESS" 'crlHelper()(address)' --rpc-url "$RPC_URL")" \
    "$CRL_HELPER_ADDRESS"
[[ "$(cast call "$DEPENDENCY_CONFIG_ADDRESS" 'dependencyConfigState()(uint8)' --rpc-url "$RPC_URL")" == "1" ]] \
    || die "PccsDependencyConfig is not Active"
[[ "$(cast call "$DEPENDENCY_CONFIG_ADDRESS" 'pendingExecutableAt()(uint64)' --rpc-url "$RPC_URL")" == "0" ]] \
    || die "PccsDependencyConfig has an unexpected pending update"

assert_address_eq \
    "AutomataPcsDaoV2 resolver" \
    "$(cast call "$PCS_DAO_ADDRESS" 'resolver()(address)' --rpc-url "$RPC_URL")" \
    "$STORAGE_ADDRESS"
assert_address_eq \
    "AutomataPcsDaoV2 CRL helper" \
    "$(cast call "$PCS_DAO_ADDRESS" 'crlLib()(address)' --rpc-url "$RPC_URL")" \
    "$CRL_HELPER_ADDRESS"
assert_address_eq \
    "AutomataPcsDaoV2 PCK helper" \
    "$(cast call "$PCS_DAO_ADDRESS" 'x509()(address)' --rpc-url "$RPC_URL")" \
    "$PCK_HELPER_ADDRESS"
PCS_P256_ADDRESS="$(cast call "$PCS_DAO_ADDRESS" 'P256_VERIFIER()(address)' --rpc-url "$RPC_URL")"
assert_address_eq \
    "AutomataPckDaoV2 resolver" \
    "$(cast call "$PCK_DAO_ADDRESS" 'resolver()(address)' --rpc-url "$RPC_URL")" \
    "$STORAGE_ADDRESS"
assert_address_eq \
    "AutomataPckDaoV2 PCS DAO" \
    "$(cast call "$PCK_DAO_ADDRESS" 'Pcs()(address)' --rpc-url "$RPC_URL")" \
    "$PCS_DAO_ADDRESS"
assert_address_eq \
    "AutomataPckDaoV2 CRL helper" \
    "$(cast call "$PCK_DAO_ADDRESS" 'crlLib()(address)' --rpc-url "$RPC_URL")" \
    "$CRL_HELPER_ADDRESS"
assert_address_eq \
    "AutomataPckDaoV2 PCK helper" \
    "$(cast call "$PCK_DAO_ADDRESS" 'x509()(address)' --rpc-url "$RPC_URL")" \
    "$PCK_HELPER_ADDRESS"
assert_address_eq \
    "AutomataPckDaoV2 P256 verifier" \
    "$(cast call "$PCK_DAO_ADDRESS" 'P256_VERIFIER()(address)' --rpc-url "$RPC_URL")" \
    "$PCS_P256_ADDRESS"

AUTHORIZED="$(
    cast call "$CRL_HELPER_ADDRESS" \
        'authorizedIndexers(address)(bool)' "$PCS_DAO_ADDRESS" \
        --rpc-url "$RPC_URL"
)"
[[ "$AUTHORIZED" == "true" ]] || die "AutomataPcsDaoV2 is not an authorized CRL indexer"

require_storage_writer AutomataPcsDaoV2 "$STORAGE_ADDRESS" "$PCS_DAO_ADDRESS"
require_storage_writer AutomataPckDaoV2 "$STORAGE_ADDRESS" "$PCK_DAO_ADDRESS"
if [[ "${EXPECT_LEGACY_PCS_REVOKED:-false}" == "true" ]]; then
    require_storage_writer_revoked AutomataPcsDao "$STORAGE_ADDRESS" "$LEGACY_PCS_DAO_ADDRESS"
else
    require_storage_writer AutomataPcsDao "$STORAGE_ADDRESS" "$LEGACY_PCS_DAO_ADDRESS"
fi

cast call "$PCS_DAO_ADDRESS" \
    'getCertificateById(uint8)(bytes,bytes)' 0 \
    --rpc-url "$RPC_URL" >/dev/null \
    || die "AutomataPcsDaoV2 cannot read ROOT collateral from AutomataDaoStorage"

cast call "$PCK_DAO_ADDRESS" \
    'getCert(string,string,string,string)(bytes)' "" "" "" "" \
    --rpc-url "$RPC_URL" >/dev/null \
    || die "AutomataPckDaoV2 cannot read through AutomataDaoStorage"

CRL_HELPER_OWNER="$(cast call "$CRL_HELPER_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
validate_crl_v2_runtime_code "$CRL_HELPER_OWNER"

require_all_stored_crls_indexed "$PCCS_FILE"

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

require_configurable_dao() {
    local label="$1"
    local dao="$2"
    local storage="$3"
    local expected_eval="${4:-}"
    require_contract_code "$label" "$dao"
    assert_address_eq \
        "$label PCS DAO" \
        "$(cast call "$dao" 'Pcs()(address)' --rpc-url "$RPC_URL")" \
        "$PCS_DAO_ADDRESS"
    assert_address_eq \
        "$label CRL helper" \
        "$(cast call "$dao" 'crlLibAddr()(address)' --rpc-url "$RPC_URL")" \
        "$CRL_HELPER_ADDRESS"
    assert_address_eq \
        "$label resolver" \
        "$(cast call "$dao" 'resolver()(address)' --rpc-url "$RPC_URL")" \
        "$storage"
    if [[ -n "$expected_eval" ]]; then
        [[ "$(cast call "$dao" 'TCB_EVALUATION_NUMBER()(uint32)' --rpc-url "$RPC_URL")" == "$expected_eval" ]] \
            || die "$label evaluation number mismatch"
    fi
    require_storage_writer "$label" "$storage" "$dao"
    require_attester_roles "$label" "$dao"
}

require_configurable_dao AutomataTcbEvalDaoCrlV2 "$TCB_EVAL_DAO_ADDRESS" "$STORAGE_ADDRESS"
STORAGE_V2_ADDRESS="$(json_address "$PCCS_FILE" AutomataDaoStorageV2)"
for eval_number in $TCB_EVALUATION_NUMBERS; do
    enclave_address="$(json_address "$PCCS_FILE" "AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${eval_number}")"
    fmspc_address="$(json_address "$PCCS_FILE" "AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${eval_number}")"
    require_configurable_dao "Enclave Identity eval $eval_number" "$enclave_address" "$STORAGE_ADDRESS" "$eval_number"
    require_configurable_dao "FMSPC V2 eval $eval_number" "$fmspc_address" "$STORAGE_V2_ADDRESS" "$eval_number"
    assert_address_eq \
        "PCCSRouter evaluation $eval_number Enclave Identity DAO" \
        "$(cast call "$ROUTER_ADDRESS" 'qeIdDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")" \
        "$enclave_address"
    assert_address_eq \
        "PCCSRouter evaluation $eval_number FMSPC DAO" \
        "$(cast call "$ROUTER_ADDRESS" 'fmspcTcbDaoVersionedAddr(uint32)(address)' "$eval_number" --rpc-url "$RPC_URL")" \
        "$fmspc_address"
done

if [[ "${EXPECT_LEGACY_PCS_REVOKED:-false}" == "true" ]]; then
    success "Post-revocation CRL V2 deployment is consistent"
else
    success "Pre-revocation CRL V2 deployment is consistent; legacy PCS remains available for evaluation 19"
fi
