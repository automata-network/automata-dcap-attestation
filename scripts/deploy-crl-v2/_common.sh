#!/usr/bin/env bash

set -Eeuo pipefail

DCAP_CRL_V2_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DCAP_ROOT="${DCAP_ROOT:-$(cd "$DCAP_CRL_V2_SCRIPT_DIR/../.." && pwd)}"
PCCS_ROOT="${PCCS_ROOT:-$DCAP_ROOT/evm/lib/automata-on-chain-pccs}"

[[ -f "$PCCS_ROOT/script/crl-v2/_common.sh" ]] || {
    printf '[ERROR] PCCS CRL V2 scripts not found under %s\n' "$PCCS_ROOT" >&2
    exit 1
}

# shellcheck source=../../evm/lib/automata-on-chain-pccs/script/crl-v2/_common.sh
source "$PCCS_ROOT/script/crl-v2/_common.sh"

load_attester_workers() {
    local configured_addresses="${ATTESTER_ADDRESSES:-}"
    local candidate
    local existing
    local duplicate

    if [[ -z "$configured_addresses" ]]; then
        configured_addresses="${ATTESTER_ADDRESS:-}"
    elif [[ -n "${ATTESTER_ADDRESS:-}" ]]; then
        info "ATTESTER_ADDRESSES is set; ignoring legacy ATTESTER_ADDRESS"
    fi

    [[ -n "$configured_addresses" ]] \
        || die "ATTESTER_ADDRESSES is required (legacy ATTESTER_ADDRESS is also accepted)"

    # Accept either a shell-friendly space-separated list or a comma-separated
    # list supplied by deployment tooling.
    configured_addresses="${configured_addresses//,/ }"
    read -r -a ATTESTER_WORKERS <<< "$configured_addresses"
    ((${#ATTESTER_WORKERS[@]} > 0)) \
        || die "ATTESTER_ADDRESSES must contain at least one worker address"

    local -a unique_workers=()
    for candidate in "${ATTESTER_WORKERS[@]}"; do
        [[ "$candidate" =~ ^0x[0-9a-fA-F]{40}$ ]] \
            || die "Invalid attester worker address: $candidate"
        [[ "${candidate,,}" != "0x0000000000000000000000000000000000000000" ]] \
            || die "Attester worker address cannot be the zero address"

        duplicate=false
        for existing in "${unique_workers[@]}"; do
            if [[ "${candidate,,}" == "${existing,,}" ]]; then
                duplicate=true
                break
            fi
        done
        if [[ "$duplicate" == "false" ]]; then
            unique_workers+=("$candidate")
        fi
    done

    ATTESTER_WORKERS=("${unique_workers[@]}")
}

grant_attester_roles() {
    local label="$1"
    local dao="$2"
    local worker
    local has_role

    for worker in "${ATTESTER_WORKERS[@]}"; do
        has_role="$(cast call "$dao" 'hasAnyRole(address,uint256)(bool)' "$worker" 1 --rpc-url "$RPC_URL")"
        if [[ "$has_role" == "true" ]]; then
            success "$label already grants ATTESTER_ROLE to $worker"
            continue
        fi

        info "Granting $label ATTESTER_ROLE to $worker"
        cast send "$dao" \
            'grantRoles(address,uint256)' "$worker" 1 \
            --rpc-url "$RPC_URL" \
            "${CAST_WALLET_ARGS[@]}"
        [[ "$(cast call "$dao" 'hasAnyRole(address,uint256)(bool)' "$worker" 1 --rpc-url "$RPC_URL")" == "true" ]] \
            || die "$label ATTESTER_ROLE grant did not take effect for $worker"
    done
}

require_attester_roles() {
    local label="$1"
    local dao="$2"
    local worker

    for worker in "${ATTESTER_WORKERS[@]}"; do
        [[ "$(cast call "$dao" 'hasAnyRole(address,uint256)(bool)' "$worker" 1 --rpc-url "$RPC_URL")" == "true" ]] \
            || die "$label does not grant ATTESTER_ROLE to $worker"
    done
}

registry_pccs_file() {
    printf '%s/rust-crates/libraries/network-registry/deployment/current/%s/onchain_pccs.json\n' \
        "$DCAP_ROOT" "$CHAIN_ID"
}

registry_dcap_file() {
    printf '%s/rust-crates/libraries/network-registry/deployment/current/%s/dcap.json\n' \
        "$DCAP_ROOT" "$CHAIN_ID"
}

require_all_stored_crls_indexed() {
    local pccs_file="$1"
    local pcs_dao
    local crl_helper

    pcs_dao="$(json_address "$pccs_file" AutomataPcsDaoV2)"
    crl_helper="$(json_address "$pccs_file" X509CRLHelperV2)"

    for ca_name in root processor platform; do
        local ca
        local der_hash
        local complete
        ca="$(ca_number "$ca_name")"
        der_hash="$(stored_crl_hash "$pcs_dao" "$ca")"
        complete="$(
            cast call "$crl_helper" \
                'indexedCrls(bytes32)(bool)' "$der_hash" \
                --rpc-url "$RPC_URL"
        )"
        [[ "$complete" == "true" ]] \
            || die "${ca_name^^} CRL $der_hash is not fully indexed"
    done
}

require_exact_index_v2() {
    local crl_helper="$1"
    cast call "$crl_helper" \
        'crlRevokedSetHashes(bytes32)(bytes32)' \
        0x0000000000000000000000000000000000000000000000000000000000000000 \
        --rpc-url "$RPC_URL" >/dev/null \
        || die "CRL helper does not expose exact-index V2"
}
