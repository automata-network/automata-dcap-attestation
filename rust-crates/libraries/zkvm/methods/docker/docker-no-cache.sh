#!/usr/bin/env bash
# Per-invocation wrapper for the official SDK CLIs. Never changes daemon
# configuration or prunes shared caches; only bypasses build layers for this job.
set -euo pipefail
: "${REPRO_DOCKER_BIN:?Set the absolute path of the real docker executable}"
if test "${1:-}" = build; then
  shift
  exec "$REPRO_DOCKER_BIN" build --no-cache --platform linux/amd64 "$@"
elif test "${1:-}" = run; then
  shift
  exec "$REPRO_DOCKER_BIN" run --cpus=4 --memory=8g --pids-limit=512 \
    --cap-drop=ALL --security-opt=no-new-privileges "$@"
else
  exec "$REPRO_DOCKER_BIN" "$@"
fi
