#!/usr/bin/env bash
# Shared actionlint archive pin and verification used by CI and local setup.

set -uo pipefail

actionlint_archive_sha() {
    printf '%s\n' 023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757
}

verify_actionlint_archive() {
    local archive="$1"
    printf '%s  %s\n' "$(actionlint_archive_sha)" "$archive" | sha256sum -c - >/dev/null 2>&1
}

if [ "${1:-}" = verify ]; then
    [ "$#" -eq 2 ] || exit 2
    verify_actionlint_archive "$2"
fi
