#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

usage() {
    cat <<'EOF'
Usage:
  verify-contract-sources.sh [options]

Verifies the CRL V2 deployment sources recorded in deployment/<chain-id>.json:
  - X509CRLHelperV2
  - PccsDependencyConfig
  - AutomataPcsDaoV2
  - AutomataPckDaoV2
  - AutomataTcbEvalDaoCrlV2
  - AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_*
  - AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_*

Required environment:
  RPC_URL
  CHAIN_ID

Optional environment:
  CONTRACT_VERIFIER             blockscout or etherscan
  CONTRACT_VERIFIER_URL        Explorer verification API URL
  CONTRACT_VERIFIER_API_KEY    Optional verifier API key override
  ETHERSCAN_API_KEY             Required for Etherscan unless overridden above
  TCB_EVALUATION_NUMBERS        Space- or comma-separated evaluation numbers

Options:
  --verifier blockscout|etherscan
      Defaults to CONTRACT_VERIFIER, then blockscout.
  --verifier-url URL
      Defaults to CONTRACT_VERIFIER_URL. Required for Blockscout except that
      chain 1315 defaults to https://aeneid.datanetscan.io/api/.
  --evals "20 21"
      Verify only the listed evaluation deployments. By default, evaluation
      numbers are discovered from the CrlV2 keys in the deployment file.
  --deployment-file PATH
      Defaults to automata-on-chain-pccs/deployment/<chain-id>.json.
  --no-watch
      Submit verification requests without waiting for the final result.
  -h, --help

Examples:
  # Story Aeneid / DATA Network Blockscout
  ./scripts/deploy-crl-v2/verify-contract-sources.sh \
    --verifier blockscout \
    --verifier-url https://aeneid.datanetscan.io/api/

  # Etherscan-family explorer
  ETHERSCAN_API_KEY=... \
    ./scripts/deploy-crl-v2/verify-contract-sources.sh \
      --verifier etherscan
EOF
}

VERIFIER="${CONTRACT_VERIFIER:-blockscout}"
VERIFIER_URL="${CONTRACT_VERIFIER_URL:-}"
VERIFIER_KEY="${CONTRACT_VERIFIER_API_KEY:-${VERIFIER_API_KEY:-}}"
EVALUATIONS="${TCB_EVALUATION_NUMBERS:-}"
DEPLOYMENT_FILE=""
WATCH=true

while (($# > 0)); do
    case "$1" in
        --verifier)
            [[ $# -ge 2 ]] || die "--verifier requires a value"
            VERIFIER="$2"
            shift 2
            ;;
        --verifier-url)
            [[ $# -ge 2 ]] || die "--verifier-url requires a value"
            VERIFIER_URL="$2"
            shift 2
            ;;
        --evals)
            [[ $# -ge 2 ]] || die "--evals requires a value"
            EVALUATIONS="$2"
            shift 2
            ;;
        --deployment-file)
            [[ $# -ge 2 ]] || die "--deployment-file requires a value"
            DEPLOYMENT_FILE="$2"
            shift 2
            ;;
        --no-watch)
            WATCH=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
done

case "$VERIFIER" in
    blockscout|etherscan) ;;
    *) die "Unsupported verifier '$VERIFIER'; expected blockscout or etherscan" ;;
esac

init_network
require_command forge
require_command jq

if [[ -z "$DEPLOYMENT_FILE" ]]; then
    DEPLOYMENT_FILE="$PCCS_ROOT/deployment/$CHAIN_ID.json"
fi
[[ -f "$DEPLOYMENT_FILE" ]] || die "Deployment file not found: $DEPLOYMENT_FILE"

if [[ "$VERIFIER" == "blockscout" ]]; then
    if [[ -z "$VERIFIER_URL" && "$CHAIN_ID" == "1315" ]]; then
        VERIFIER_URL="https://aeneid.datanetscan.io/api/"
    fi
    [[ -n "$VERIFIER_URL" ]] \
        || die "--verifier-url is required for Blockscout on chain $CHAIN_ID"

    # foundry.toml contains Etherscan environment interpolation even when the
    # selected verifier is Blockscout. No Etherscan request uses this value.
    export ETHERSCAN_API_KEY="${ETHERSCAN_API_KEY:-unused-for-blockscout}"
    if [[ "$WATCH" == "true" ]]; then
        require_command curl
    fi
else
    if [[ -z "$VERIFIER_KEY" ]]; then
        VERIFIER_KEY="${ETHERSCAN_API_KEY:-}"
    fi
    [[ -n "$VERIFIER_KEY" ]] \
        || die "ETHERSCAN_API_KEY or CONTRACT_VERIFIER_API_KEY is required for Etherscan"
fi
if [[ -n "$VERIFIER_KEY" ]]; then
    # Keep API keys out of the forge command line and process listing.
    export VERIFIER_API_KEY="$VERIFIER_KEY"
fi

if [[ -z "$EVALUATIONS" ]]; then
    EVALUATIONS="$(
        jq -r '
            keys[]
            | select(
                startswith("AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_")
                or startswith("AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_")
            )
            | capture("_tcbeval_(?<evaluation>[0-9]+)$").evaluation
        ' "$DEPLOYMENT_FILE" | sort -n -u | tr '\n' ' '
    )"
fi
EVALUATIONS="${EVALUATIONS//,/ }"
read -r -a EVALUATION_LIST <<< "$EVALUATIONS"
((${#EVALUATION_LIST[@]} > 0)) \
    || die "No CrlV2 evaluation deployments found in $DEPLOYMENT_FILE"

declare -A SEEN_EVALUATIONS=()
for evaluation in "${EVALUATION_LIST[@]}"; do
    [[ "$evaluation" =~ ^[1-9][0-9]*$ ]] \
        || die "Invalid TCB evaluation number: $evaluation"
    [[ -z "${SEEN_EVALUATIONS[$evaluation]:-}" ]] \
        || die "Duplicate TCB evaluation number: $evaluation"
    SEEN_EVALUATIONS["$evaluation"]=1
done

json_addr() {
    json_address "$DEPLOYMENT_FILE" "$1"
}

CRL_HELPER_ADDRESS="$(json_addr X509CRLHelperV2)"
DEPENDENCY_CONFIG_ADDRESS="$(json_addr PccsDependencyConfig)"
PCS_DAO_ADDRESS="$(json_addr AutomataPcsDaoV2)"
PCK_DAO_ADDRESS="$(json_addr AutomataPckDaoV2)"
TCB_EVAL_DAO_ADDRESS="$(json_addr AutomataTcbEvalDaoCrlV2)"
STORAGE_ADDRESS="$(json_addr AutomataDaoStorage)"
STORAGE_V2_ADDRESS="$(json_addr AutomataDaoStorageV2)"
PCK_HELPER_ADDRESS="$(json_addr PCKHelper)"
TCB_EVAL_HELPER_ADDRESS="$(json_addr TcbEvalHelper)"
ENCLAVE_HELPER_ADDRESS="$(json_addr EnclaveIdentityHelper)"
FMSPC_HELPER_ADDRESS="$(json_addr FmspcTcbHelper)"
FMSPC_HELPER_V2_ADDRESS="$(json_addr FmspcTcbHelperV2)"

for entry in \
    "X509CRLHelperV2:$CRL_HELPER_ADDRESS" \
    "PccsDependencyConfig:$DEPENDENCY_CONFIG_ADDRESS" \
    "AutomataPcsDaoV2:$PCS_DAO_ADDRESS" \
    "AutomataPckDaoV2:$PCK_DAO_ADDRESS" \
    "AutomataTcbEvalDaoCrlV2:$TCB_EVAL_DAO_ADDRESS"; do
    require_contract_code "${entry%%:*}" "${entry#*:}"
done

OWNER_ADDRESS="$(cast call "$CRL_HELPER_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")"
[[ "$OWNER_ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ ]] \
    || die "Could not read the CRL V2 deployment owner"
assert_address_eq \
    "PccsDependencyConfig owner" \
    "$(cast call "$DEPENDENCY_CONFIG_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")" \
    "$OWNER_ADDRESS"
assert_address_eq \
    "AutomataTcbEvalDaoCrlV2 owner" \
    "$(cast call "$TCB_EVAL_DAO_ADDRESS" 'owner()(address)' --rpc-url "$RPC_URL")" \
    "$OWNER_ADDRESS"

P256_ADDRESS="$(cast call "$PCS_DAO_ADDRESS" 'P256_VERIFIER()(address)' --rpc-url "$RPC_URL")"
[[ "$P256_ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ ]] \
    || die "Could not read the P256 verifier from AutomataPcsDaoV2"

VERIFY_ARGS=(
    --chain "$CHAIN_ID"
    --rpc-url "$RPC_URL"
    --verifier "$VERIFIER"
    --retries "${VERIFY_RETRIES:-5}"
    --delay "${VERIFY_DELAY:-5}"
)
if [[ -n "$VERIFIER_URL" ]]; then
    VERIFY_ARGS+=(--verifier-url "$VERIFIER_URL")
fi
if [[ "$WATCH" == "true" ]]; then
    VERIFY_ARGS+=(--watch)
fi

verified=0
failed=0
declare -a FAILED_CONTRACTS=()

verify_contract() {
    local label="$1"
    local address="$2"
    local contract="$3"
    local constructor_args="$4"

    require_contract_code "$label" "$address"
    local forge_output
    local forge_status
    local verified_on_explorer=true

    info "Verifying $label at $address"
    set +e
    forge_output="$(
        cd "$PCCS_ROOT"
        forge verify-contract \
            "${VERIFY_ARGS[@]}" \
            "$address" \
            "$contract" \
            --constructor-args "$constructor_args" 2>&1
    )"
    forge_status=$?
    set -e
    printf '%s\n' "$forge_output"

    if [[ "$WATCH" == "true" && "$VERIFIER" == "blockscout" ]]; then
        verified_on_explorer=false
        if wait_for_blockscout_verification "$address"; then
            verified_on_explorer=true
        fi
    elif [[ "$WATCH" == "true" && "$forge_output" == *"Fail -"* ]]; then
        verified_on_explorer=false
    fi

    if [[ "$forge_status" -eq 0 && "$verified_on_explorer" == "true" ]]; then
        success "$label source verification accepted"
        verified=$((verified + 1))
    else
        printf '[ERROR] %s source verification failed\n' "$label" >&2
        FAILED_CONTRACTS+=("$label:$address")
        failed=$((failed + 1))
    fi
}

wait_for_blockscout_verification() {
    local address="$1"
    local status_url="${VERIFIER_URL%/}?module=contract&action=getsourcecode&address=${address}"
    local attempts="${VERIFY_STATUS_RETRIES:-5}"
    local delay="${VERIFY_STATUS_DELAY:-3}"
    local response

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if response="$(curl -fsS --max-time 30 "$status_url" 2>/dev/null)" \
            && jq -e '
                .status == "1"
                and (.result | type == "array")
                and (.result | length > 0)
                and (.result[0].ContractName // "") != ""
            ' >/dev/null <<<"$response"; then
            return 0
        fi
        if ((attempt < attempts)); then
            sleep "$delay"
        fi
    done
    return 1
}

info "Building automata-on-chain-pccs with its deployment compiler settings"
(cd "$PCCS_ROOT" && forge build -q)

printf 'CRL V2 source verification\n'
printf '  chain ID: %s\n' "$CHAIN_ID"
printf '  verifier: %s\n' "$VERIFIER"
if [[ -n "$VERIFIER_URL" ]]; then
    printf '  verifier URL: %s\n' "$VERIFIER_URL"
fi
printf '  deployment file: %s\n' "$DEPLOYMENT_FILE"
printf '  owner: %s\n' "$OWNER_ADDRESS"
printf '  evaluations: %s\n' "${EVALUATION_LIST[*]}"

verify_contract \
    X509CRLHelperV2 \
    "$CRL_HELPER_ADDRESS" \
    "src/helpers/X509CRLHelperV2.sol:X509CRLHelperV2" \
    "$(cast abi-encode 'constructor(address)' "$OWNER_ADDRESS")"

verify_contract \
    PccsDependencyConfig \
    "$DEPENDENCY_CONFIG_ADDRESS" \
    "src/automata_pccs/shared/PccsDependencyConfig.sol:PccsDependencyConfig" \
    "$(cast abi-encode 'constructor(address)' "$OWNER_ADDRESS")"

verify_contract \
    AutomataPcsDaoV2 \
    "$PCS_DAO_ADDRESS" \
    "src/automata_pccs/AutomataPcsDaoV2.sol:AutomataPcsDaoV2" \
    "$(cast abi-encode 'constructor(address,address,address,address)' \
        "$STORAGE_ADDRESS" \
        "$P256_ADDRESS" \
        "$PCK_HELPER_ADDRESS" \
        "$DEPENDENCY_CONFIG_ADDRESS")"

verify_contract \
    AutomataPckDaoV2 \
    "$PCK_DAO_ADDRESS" \
    "src/automata_pccs/AutomataPckDaoV2.sol:AutomataPckDaoV2" \
    "$(cast abi-encode 'constructor(address,address,address,address)' \
        "$STORAGE_ADDRESS" \
        "$P256_ADDRESS" \
        "$DEPENDENCY_CONFIG_ADDRESS" \
        "$PCK_HELPER_ADDRESS")"

verify_contract \
    AutomataTcbEvalDaoCrlV2 \
    "$TCB_EVAL_DAO_ADDRESS" \
    "src/automata_pccs/AutomataTcbEvalDao.sol:AutomataTcbEvalDao" \
    "$(cast abi-encode 'constructor(address,address,address,address,address,address)' \
        "$STORAGE_ADDRESS" \
        "$P256_ADDRESS" \
        "$DEPENDENCY_CONFIG_ADDRESS" \
        "$TCB_EVAL_HELPER_ADDRESS" \
        "$PCK_HELPER_ADDRESS" \
        "$OWNER_ADDRESS")"

for evaluation in "${EVALUATION_LIST[@]}"; do
    enclave_key="AutomataEnclaveIdentityDaoVersionedCrlV2_tcbeval_${evaluation}"
    fmspc_key="AutomataFmspcTcbDaoVersionedV2CrlV2_tcbeval_${evaluation}"
    enclave_address="$(json_addr "$enclave_key")"
    fmspc_address="$(json_addr "$fmspc_key")"

    assert_address_eq \
        "$enclave_key owner" \
        "$(cast call "$enclave_address" 'owner()(address)' --rpc-url "$RPC_URL")" \
        "$OWNER_ADDRESS"
    assert_address_eq \
        "$fmspc_key owner" \
        "$(cast call "$fmspc_address" 'owner()(address)' --rpc-url "$RPC_URL")" \
        "$OWNER_ADDRESS"
    [[ "$(cast call "$enclave_address" 'TCB_EVALUATION_NUMBER()(uint32)' --rpc-url "$RPC_URL")" == "$evaluation" ]] \
        || die "$enclave_key evaluation number mismatch"
    [[ "$(cast call "$fmspc_address" 'TCB_EVALUATION_NUMBER()(uint32)' --rpc-url "$RPC_URL")" == "$evaluation" ]] \
        || die "$fmspc_key evaluation number mismatch"

    verify_contract \
        "$enclave_key" \
        "$enclave_address" \
        "src/automata_pccs/versioned/AutomataEnclaveIdentityDaoVersioned.sol:AutomataEnclaveIdentityDaoVersioned" \
        "$(cast abi-encode 'constructor(address,address,address,address,address,address,uint32)' \
            "$STORAGE_ADDRESS" \
            "$P256_ADDRESS" \
            "$DEPENDENCY_CONFIG_ADDRESS" \
            "$ENCLAVE_HELPER_ADDRESS" \
            "$PCK_HELPER_ADDRESS" \
            "$OWNER_ADDRESS" \
            "$evaluation")"

    verify_contract \
        "$fmspc_key" \
        "$fmspc_address" \
        "src/automata_pccs/versioned/AutomataFmspcTcbDaoVersionedV2.sol:AutomataFmspcTcbDaoVersionedV2" \
        "$(cast abi-encode 'constructor(address,address,address,address,address,address,address,uint32)' \
            "$STORAGE_V2_ADDRESS" \
            "$P256_ADDRESS" \
            "$DEPENDENCY_CONFIG_ADDRESS" \
            "$FMSPC_HELPER_ADDRESS" \
            "$FMSPC_HELPER_V2_ADDRESS" \
            "$PCK_HELPER_ADDRESS" \
            "$OWNER_ADDRESS" \
            "$evaluation")"
done

printf 'Summary: accepted=%d, failed=%d\n' "$verified" "$failed"
if ((failed > 0)); then
    printf 'Failed contracts:\n' >&2
    printf '  %s\n' "${FAILED_CONTRACTS[@]}" >&2
    exit 1
fi
success "All CRL V2 contract sources are verified or already verified"
