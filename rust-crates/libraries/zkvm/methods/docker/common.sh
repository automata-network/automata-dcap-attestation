#!/usr/bin/env bash
# Bash 3.2 / macOS and Linux helpers; no GNU coreutils requirement.

repro_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

# Resolve directory symlinks (/tmp -> /private/tmp on macOS). In particular,
# SP1 requires Cargo's target directory and canonical workspace to agree.
repro_physical_file() {
  (cd -P -- "$(dirname -- "$1")" && printf '%s/%s\n' "$PWD" "$(basename -- "$1")")
}

repro_native_id() {
  # Keep the complete stdout separately. Compare its one 32-byte ID, not path
  # labels or other host-dependent CLI presentation.
  local repro_ids
  repro_ids="$(LC_ALL=C grep -Eo '(0x)?[[:xdigit:]]{64}' "$1" | sed 's/^0x//' | tr 'A-F' 'a-f')" || return 1
  test "$(printf '%s\n' "$repro_ids" | wc -l | tr -d ' ')" = 1 || return 1
  printf '%s\n' "$repro_ids" | LC_ALL=C grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '0x%s\n' "$repro_ids"
}
