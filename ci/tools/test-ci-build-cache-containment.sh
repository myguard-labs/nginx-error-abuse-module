#!/usr/bin/env bash
# The cache fixture must ignore build roots inherited from its caller.
set -euo pipefail
repo="$(git rev-parse --show-toplevel)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/ci-build-cache-containment.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/inherited/nginx-1.31.3-asan"
printf 'caller-owned sentinel\n' > "$tmp/expected"
cp "$tmp/expected" "$tmp/inherited/nginx-1.31.3-asan/sentinel"
status=0
BUILD_ROOT="$tmp/inherited" bash "$repo/ci/tools/test-ci-build-cache.sh" > "$tmp/cache.log" 2>&1 || status=$?
if ! cmp -s "$tmp/expected" "$tmp/inherited/nginx-1.31.3-asan/sentinel"; then
    cat "$tmp/cache.log" >&2
    echo 'FAIL: inherited BUILD_ROOT sentinel changed or removed' >&2
    exit 1
fi
if [[ "$(find "$tmp/inherited" -mindepth 1 | wc -l)" -ne 2 ]]; then
    cat "$tmp/cache.log" >&2
    echo 'FAIL: cache fixture wrote to inherited BUILD_ROOT' >&2
    exit 1
fi
cat "$tmp/cache.log"
[[ "$status" -eq 0 ]] || exit "$status"
echo 'ok: inherited BUILD_ROOT untouched; cache fixture succeeded'
