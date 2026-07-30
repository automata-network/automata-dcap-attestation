#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

EXPECT_LEGACY_PCS_REVOKED=true "$SCRIPT_DIR/06-verify.sh"

init_network
PCCS_FILE="$(registry_pccs_file)"
DCAP_FILE="$(registry_dcap_file)"
ROUTER_ADDRESS="$(json_address "$DCAP_FILE" PCCSRouter)"
RETIRED_TCB_EVALUATION_NUMBER="${RETIRED_TCB_EVALUATION_NUMBER:-19}"
zero_address="0x0000000000000000000000000000000000000000"

assert_address_eq \
    "retired evaluation Enclave Identity mapping" \
    "$(cast call "$ROUTER_ADDRESS" 'qeIdDaoVersionedAddr(uint32)(address)' "$RETIRED_TCB_EVALUATION_NUMBER" --rpc-url "$RPC_URL")" \
    "$zero_address"
assert_address_eq \
    "retired evaluation FMSPC mapping" \
    "$(cast call "$ROUTER_ADDRESS" 'fmspcTcbDaoVersionedAddr(uint32)(address)' "$RETIRED_TCB_EVALUATION_NUMBER" --rpc-url "$RPC_URL")" \
    "$zero_address"

require_all_stored_crls_indexed "$PCCS_FILE"
success "Legacy PCS is revoked, evaluation $RETIRED_TCB_EVALUATION_NUMBER is retired, and active CRLs remain indexed"
