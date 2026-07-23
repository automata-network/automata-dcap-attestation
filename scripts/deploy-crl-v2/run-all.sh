#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

# Prepare the keystore once. Child scripts reuse the exported password file,
# so an interactive run asks for the password only once.
init_deployment_context

steps=(
    01-deploy-pccs-v2.sh
    02-index-stored-crls.sh
    03-deploy-dependent-daos.sh
    04-sync-deployment.sh
    05-update-router.sh
    06-verify.sh
)

for index in "${!steps[@]}"; do
    step="${steps[$index]}"
    info "[$((index + 1))/${#steps[@]}] Running $step"
    "$SCRIPT_DIR/$step"
done

success "CRL V2 rollout completed without revoking legacy PCS"
info "After evaluation 19 expires, run 07-revoke-legacy-pcs.sh and 08-verify-post-revoke.sh separately"
