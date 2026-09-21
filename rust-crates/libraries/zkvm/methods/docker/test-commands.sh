#!/usr/bin/env bash
# Command-shape/argument guards only. No Docker daemon, builds or proofs used.
set -euo pipefail
test_scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test "$(REPRO_DOCKER_BIN=/bin/echo bash "$test_scripts/docker-no-cache.sh" build -f Dockerfile /src)" = \
  'build --no-cache --platform linux/amd64 -f Dockerfile /src'
test "$(REPRO_DOCKER_BIN=/bin/echo bash "$test_scripts/docker-no-cache.sh" run --rm example-image true)" = \
  'run --cpus=4 --memory=8g --pids-limit=512 --cap-drop=ALL --security-opt=no-new-privileges --rm example-image true'
test "$(REPRO_DOCKER_BIN=/bin/echo bash "$test_scripts/docker-no-cache.sh" version --format version)" = \
  'version --format version'
test_status=0
bash "$test_scripts/reproduce-pico.sh" HEAD rust:latest >/dev/null 2>&1 || test_status=$?
test "$test_status" -eq 2
test_status=0
bash "$test_scripts/reproduce-official.sh" unknown HEAD >/dev/null 2>&1 || test_status=$?
test "$test_status" -eq 2
test_status=0
bash "$test_scripts/run-handoff.sh" risc0 unknown >/dev/null 2>&1 || test_status=$?
test "$test_status" -eq 2
test_status=0
bash "$test_scripts/run-handoff.sh" risc0 strict extra >/dev/null 2>&1 || test_status=$?
test "$test_status" -eq 2
printf '%s\n' '7 Docker build command/argument checks passed (no Docker execution).'
