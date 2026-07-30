#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

init_network

SOURCE_FILE="$PCCS_ROOT/deployment/$CHAIN_ID.json"
TCB_EVALUATION_NUMBERS="${TCB_EVALUATION_NUMBERS:-20 21}"
keys=(
    X509CRLHelperV2
    PccsDependencyConfig
    AutomataPcsDaoV2
    AutomataPckDaoV2
    AutomataTcbEvalDaoCrlV2
)
for eval_number in $TCB_EVALUATION_NUMBERS; do
    keys+=(
        "AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${eval_number}"
        "AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${eval_number}"
    )
done

for key in "${keys[@]}"; do
    json_address "$SOURCE_FILE" "$key" >/dev/null
done

info "Syncing PCCS deployment into the DCAP network registry"
(
    cd "$DCAP_ROOT/rust-crates"
    ./scripts/update_pccs_deployment.sh --local "$CHAIN_ID"
)

TARGET_FILE="$(registry_pccs_file)"
for key in "${keys[@]}"; do
    source_address="$(json_address "$SOURCE_FILE" "$key")"
    target_address="$(json_address "$TARGET_FILE" "$key")"
    assert_address_eq "$key registry value" "$target_address" "$source_address"
done

success "PCCS deployment registry synchronized: $TARGET_FILE"
