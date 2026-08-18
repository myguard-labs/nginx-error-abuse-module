#!/usr/bin/env bash
# Hermetic regression tests for ci-build.sh source archive verification.
#
# Uses tiny valid tar archives plus a fake downloader/compiler so both flavors,
# cache states and failure paths run without network access or a real build.
# The copied versions.env remains the only digest source; its values are
# replaced with the fixture digests so these tests exercise pin selection as
# well as fetch-verify.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ci-build-source.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

WORK="$TMP/repo"
FIXTURES="$TMP/fixtures"
FAKEBIN="$TMP/bin"
mkdir -p "$WORK/ci/tools" "$WORK/.github/scripts" "$FIXTURES" "$FAKEBIN"
cp "$REPO_ROOT/ci/tools/ci-build.sh" "$WORK/ci/tools/"
cp "$REPO_ROOT/.github/scripts/fetch-verify.sh" "$WORK/.github/scripts/"

make_archive() {
    local flavor="$1"
    local version="$2"
    local marker="$3"
    local archive="$4"
    local source_dir="$FIXTURES/${flavor}-${version}"

    rm -rf "$source_dir"
    mkdir -p "$source_dir"
    printf '%s\n' "$marker" > "$source_dir/SOURCE_MARKER"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        'set -euo pipefail' \
        'mkdir -p objs' \
        ': > objs/Makefile' > "$source_dir/configure"
    chmod +x "$source_dir/configure"
    tar -czf "$archive" -C "$FIXTURES" "${flavor}-${version}"
}

NGINX_GOOD="$TMP/nginx-good.tar.gz"
NGINX_WRONG="$TMP/nginx-wrong.tar.gz"
ANGIE_GOOD="$TMP/angie-good.tar.gz"
ANGIE_WRONG="$TMP/angie-wrong.tar.gz"
make_archive nginx 1.31.3 nginx-pinned "$NGINX_GOOD"
make_archive nginx 1.31.3 nginx-wrong "$NGINX_WRONG"
make_archive angie 1.12.1 angie-pinned "$ANGIE_GOOD"
make_archive angie 1.12.1 angie-wrong "$ANGIE_WRONG"

nginx_sha="$(sha256sum "$NGINX_GOOD" | cut -d' ' -f1)"
angie_sha="$(sha256sum "$ANGIE_GOOD" | cut -d' ' -f1)"
write_versions() {
    local mainline_sha="$1"
    local default_sha="$2"
    local pinned_angie_sha="$3"

    printf '%s\n' \
        'NGINX_MAINLINE=1.31.3' \
        "NGINX_MAINLINE_SHA256=$mainline_sha" \
        'NGINX_STABLE=1.30.4' \
        "NGINX_STABLE_SHA256=$nginx_sha" \
        'NGINX_VERSION=1.31.3' \
        "NGINX_VERSION_SHA256=$default_sha" \
        'ANGIE_VERSION=1.12.1' \
        "ANGIE_SHA256=$pinned_angie_sha" > "$WORK/.github/versions.env"
}
write_versions "$nginx_sha" "$nginx_sha" "$angie_sha"

# Single quotes are intentional: these expansions belong to the generated
# fake curl script, not this test process.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'out=""' \
    'while (($#)); do' \
    '    if [[ "$1" == "-o" ]]; then' \
    '        out="${2:?missing curl output}"' \
    '        shift 2' \
    '    else' \
    '        shift' \
    '    fi' \
    'done' \
    ': "${FAKE_DOWNLOAD:?FAKE_DOWNLOAD must name a fixture}"' \
    'cp -- "$FAKE_DOWNLOAD" "$out"' > "$FAKEBIN/curl"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$FAKEBIN/make"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$FAKEBIN/ccache"
chmod +x "$FAKEBIN/curl" "$FAKEBIN/make" "$FAKEBIN/ccache"

rc=0

fail() {
    printf 'FAIL %s\n' "$1" >&2
    rc=1
}

run_build() {
    local build_root="$1"
    local download="$2"
    local no_cache="$3"
    local flavor="$4"
    local version="$5"
    local output="$6"
    local status=0

    (
        cd "$WORK"
        env \
            BUILD_ROOT="$build_root" \
            FAKE_DOWNLOAD="$download" \
            NO_CACHE="$no_cache" \
            PATH="$FAKEBIN:/usr/bin:/bin" \
            bash ci/tools/ci-build.sh "$flavor" "$version" asan
    ) > "$output" 2>&1 || status=$?
    return "$status"
}

expect_success() {
    local description="$1"
    local expected_marker="$2"
    local build_root="$3"
    local output="$4"
    shift 4

    if ! run_build "$build_root" "$@" "$output"; then
        fail "$description: expected success"
        sed 's/^/  | /' "$output" >&2
        return
    fi
    if [[ "$(< "$build_root/$expected_marker/SOURCE_MARKER")" != *-pinned ]]; then
        fail "$description: unpinned archive reached extraction"
        return
    fi
    printf 'ok   %s\n' "$description"
}

expect_failure() {
    local description="$1"
    local expected_status="$2"
    local expected_message="$3"
    local build_root="$4"
    local output="$5"
    shift 5
    local got=0

    run_build "$build_root" "$@" "$output" || got=$?
    if [[ "$got" -ne "$expected_status" ]]; then
        fail "$description: expected exit $expected_status, got $got"
        sed 's/^/  | /' "$output" >&2
        return
    fi
    if ! grep -Fq -- "$expected_message" "$output"; then
        fail "$description: missing message: $expected_message"
        sed 's/^/  | /' "$output" >&2
        return
    fi
    printf 'ok   %s (exit %s)\n' "$description" "$got"
}

# Genuine pinned controls: both flavor selectors accept their exact bytes.
case_root="$TMP/nginx-good-root"
mkdir -p "$case_root"
cp "$NGINX_GOOD" "$case_root/nginx-1.31.3.tar.gz"
expect_success "genuine pinned nginx cache" nginx-1.31.3-asan \
    "$case_root" "$TMP/nginx-good.out" /nonexistent 0 nginx 1.31.3

case_root="$TMP/angie-good-root"
mkdir -p "$case_root"
cp "$ANGIE_GOOD" "$case_root/angie-1.12.1.tar.gz"
expect_success "genuine pinned Angie cache" angie-1.12.1-asan \
    "$case_root" "$TMP/angie-good.out" /nonexistent 0 angie 1.12.1

expect_success "genuine pinned nginx download with NO_CACHE" nginx-1.31.3-asan \
    "$TMP/nginx-download-good-root" "$TMP/nginx-download-good.out" \
    "$NGINX_GOOD" 1 nginx 1.31.3
expect_success "genuine pinned Angie download with NO_CACHE" angie-1.12.1-asan \
    "$TMP/angie-download-good-root" "$TMP/angie-download-good.out" \
    "$ANGIE_GOOD" 1 angie 1.12.1

# A valid but wrong cache entry must be replaced before extraction. The marker
# assertion distinguishes the replacement from silently compiling the cache.
case_root="$TMP/nginx-cache-wrong-root"
mkdir -p "$case_root"
cp "$NGINX_WRONG" "$case_root/nginx-1.31.3.tar.gz"
expect_success "wrong valid nginx cache is replaced" nginx-1.31.3-asan \
    "$case_root" "$TMP/nginx-cache-wrong.out" "$NGINX_GOOD" 0 nginx 1.31.3

case_root="$TMP/angie-cache-wrong-root"
mkdir -p "$case_root"
cp "$ANGIE_WRONG" "$case_root/angie-1.12.1.tar.gz"
expect_success "wrong valid Angie cache is replaced" angie-1.12.1-asan \
    "$case_root" "$TMP/angie-cache-wrong.out" "$ANGIE_GOOD" 0 angie 1.12.1

# NO_CACHE removes any local archive, but the downloaded replacement must still
# match the pin. These wrong archives are valid tar files, not corrupt inputs.
case_root="$TMP/nginx-download-wrong-root"
expect_failure "wrong valid nginx download is rejected with NO_CACHE" 1 \
    "sha256 MISMATCH" "$case_root" "$TMP/nginx-download-wrong.out" \
    "$NGINX_WRONG" 1 nginx 1.31.3
if [[ -e "$case_root/nginx-1.31.3-asan/SOURCE_MARKER" ]]; then
    fail "wrong valid nginx download reached extraction"
fi

case_root="$TMP/angie-download-wrong-root"
expect_failure "wrong valid Angie download is rejected with NO_CACHE" 1 \
    "sha256 MISMATCH" "$case_root" "$TMP/angie-download-wrong.out" \
    "$ANGIE_WRONG" 1 angie 1.12.1
if [[ -e "$case_root/angie-1.12.1-asan/SOURCE_MARKER" ]]; then
    fail "wrong valid Angie download reached extraction"
fi

# Unknown versions must fail before a downloader can run.
expect_failure "unknown nginx version fails closed" 2 \
    "no SHA-256 pin for nginx 9.9.9" "$TMP/nginx-unknown-root" \
    "$TMP/nginx-unknown.out" /nonexistent 0 nginx 9.9.9
expect_failure "unknown Angie version fails closed" 2 \
    "no SHA-256 pin for angie 9.9.9" "$TMP/angie-unknown-root" \
    "$TMP/angie-unknown.out" /nonexistent 0 angie 9.9.9
expect_failure "unknown flavor fails closed" 2 \
    "unsupported flavor: unknown" "$TMP/flavor-unknown-root" \
    "$TMP/flavor-unknown.out" /nonexistent 0 unknown 1.31.3

write_versions "$nginx_sha" "$(printf '0%.0s' {1..64})" "$angie_sha"
expect_failure "conflicting duplicate nginx pins fail closed" 2 \
    "conflicting SHA-256 pins for nginx 1.31.3" "$TMP/conflict-root" \
    "$TMP/conflict.out" /nonexistent 0 nginx 1.31.3

write_versions invalid invalid "$angie_sha"
expect_failure "malformed nginx digest fails closed" 2 \
    "invalid SHA-256 pin for nginx 1.31.3" "$TMP/invalid-root" \
    "$TMP/invalid.out" /nonexistent 0 nginx 1.31.3
write_versions "$nginx_sha" "$nginx_sha" "$angie_sha"

if [[ "$rc" -ne 0 ]]; then
    exit "$rc"
fi
printf 'OK: ci-build source verification controls held\n'
