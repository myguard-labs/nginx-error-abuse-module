#!/usr/bin/env bash
# Portable same-run ASan provenance using a source fixture, never compilation.
set -euo pipefail
repo="$(git rev-parse --show-toplevel)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/ci-build-artifact.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
producer="$tmp/producer"
consumer="$tmp/consumer workspace"
mkdir -p "$producer/ci/tools" "$producer/.github" "$producer/src" "$tmp/consumer-tools"
cp "$repo/ci/tools/"{ci-build,build-identity,ci-build-artifact}.sh "$producer/ci/tools/"
printf 'NGINX_MAINLINE=1.31.3\nNGINX_MAINLINE_SHA256=%s\nNGINX_STABLE=1.30.4\nNGINX_STABLE_SHA256=%s\nNGINX_VERSION=1.31.3\nNGINX_VERSION_SHA256=%s\n' \
    "$(printf 'artifact fixture pin' | sha256sum | cut -d' ' -f1)" \
    "$(printf 'stable fixture pin' | sha256sum | cut -d' ' -f1)" \
    "$(printf 'artifact fixture pin' | sha256sum | cut -d' ' -f1)" > "$producer/.github/versions.env"
cp "$producer/.github/versions.env" "$tmp/valid-versions.env"
printf 'module fixture\n' > "$producer/config"
printf 'source fixture\n' > "$producer/src/module.c"
mkdir -p "$producer/ci/t/harness/src"
for file in ngx_test_probe.c ngx_test_probe_arm.c ngx_test_probe.h; do
    printf 'harness fixture\n' > "$producer/ci/t/harness/src/$file"
done
export PATH=/usr/bin:/bin
export BUILD_ROOT="$producer/.build" GITHUB_OUTPUT="$tmp/producer-outputs"
cd "$producer"
sed -i -E 's/^(NGINX_MAINLINE_SHA256|NGINX_VERSION_SHA256)=.*/\1=malformed/' .github/versions.env
if CI_BUILD_IDENTITY_ONLY=1 bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/pin-error" 2>&1; then
    echo 'FAIL: malformed fixture pin unexpectedly succeeded' >&2
    exit 1
fi
grep -Fq 'invalid SHA-256 pin for nginx 1.31.3' "$tmp/pin-error" || {
    cat "$tmp/pin-error" >&2
    echo 'FAIL: malformed fixture pin had the wrong diagnostic' >&2
    exit 1
}
[[ ! -e "$BUILD_ROOT/nginx-1.31.3-asan" ]] || { echo 'FAIL: malformed fixture pin created a build tree' >&2; exit 1; }
cp "$tmp/valid-versions.env" .github/versions.env
mkdir -p "$BUILD_ROOT/nginx-1.31.3-asan/objs"
CI_BUILD_IDENTITY_ONLY=1 bash ci/tools/ci-build.sh nginx 1.31.3 asan \
    > "$BUILD_ROOT/nginx-1.31.3-asan/.build-identity"
printf '#!/bin/sh\nprintf "portable producer binary\\n"\n' > "$BUILD_ROOT/nginx-1.31.3-asan/objs/nginx"
chmod +x "$BUILD_ROOT/nginx-1.31.3-asan/objs/nginx"
bash ci/tools/ci-build-artifact.sh export 1.31.3 "$tmp/artifact"
export EXPECTED_BUILD_IDENTITY EXPECTED_BINARY_SHA256 EXPECTED_ARTIFACT_IDENTITY EXPECTED_ARTIFACT_SHA256
EXPECTED_BUILD_IDENTITY="$(sed -n 's/^identity=//p' "$GITHUB_OUTPUT")"
EXPECTED_BINARY_SHA256="$(sed -n 's/^sha256=//p' "$GITHUB_OUTPUT")"
EXPECTED_ARTIFACT_IDENTITY="$(sed -n 's/^artifact-identity=//p' "$GITHUB_OUTPUT")"
EXPECTED_ARTIFACT_SHA256="$(sed -n 's/^artifact-sha256=//p' "$GITHUB_OUTPUT")"

fail() { echo "FAIL: $*" >&2; exit 1; }
expect_failure() {
    local label="$1" message="$2"
    shift 2
    if "$@" > "$tmp/error" 2>&1; then fail "$label unexpectedly succeeded"; fi
    grep -Fq "$message" "$tmp/error" || { cat "$tmp/error" >&2; fail "$label: wrong diagnostic ($message)"; }
    [[ -f "$BUILD_ROOT/nginx-1.31.3-asan/owned" ]] || fail "$label replaced the consumer tree on rejection"
    printf 'ok: %s (%s)\n' "$label" "$message"
}
import_artifact() { bash ci/tools/ci-build-artifact.sh import 1.31.3 "$tmp/artifact"; }
verify_installed() {
    [[ "$("$BUILD_ROOT/nginx-1.31.3-asan/objs/nginx")" == 'portable producer binary' ]] || fail 'wrong binary installed'
    [[ ! -e "$BUILD_ROOT/nginx-1.31.3-asan/.build-identity" ]] || fail 'import granted cross-run cache provenance'
}

[[ "$(wc -l < "$GITHUB_OUTPUT")" == 4 ]] || fail 'missing producer outputs'
for value in "$EXPECTED_BUILD_IDENTITY" "$EXPECTED_BINARY_SHA256" "$EXPECTED_ARTIFACT_IDENTITY" "$EXPECTED_ARTIFACT_SHA256"; do
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || fail 'invalid producer output'
done
cp -a "$producer" "$consumer"
cd "$consumer"
export BUILD_ROOT="$consumer/.build"
consumer_host_identity="$(CI_BUILD_IDENTITY_ONLY=1 bash ci/tools/ci-build.sh nginx 1.31.3 asan)"
[[ "$consumer_host_identity" != "$EXPECTED_BUILD_IDENTITY" ]] || fail 'workspace drift did not change full identity'
[[ "$(bash ci/tools/build-identity.sh --portable-asan 1.31.3)" == "$EXPECTED_ARTIFACT_IDENTITY" ]] || fail 'portable identity depends on workspace'
# If full host identity is restored in import, the assertion below must fail
# specifically with ASan consumer build identity mismatch.
if ! import_artifact > "$tmp/import.log" 2>&1; then
    cat "$tmp/import.log" >&2
    fail 'portable workspace handoff rejected'
fi
grep -Fq 'ASan artifact verified:' "$tmp/import.log" || fail 'missing artifact verification marker'
verify_installed
echo 'ok: portable workspace handoff'

# Extra consumer accelerators and even an unavailable compiler/package probe
# must not affect a binary whose producer already supplied verified provenance.
for tool in ccache mold consumer-cc dpkg-query; do
    printf '#!/bin/sh\necho unexpected-consumer-host-probe >&2\nexit 73\n' > "$tmp/consumer-tools/$tool"
    chmod +x "$tmp/consumer-tools/$tool"
done
export PATH="$tmp/consumer-tools:$PATH" CC=consumer-cc
import_artifact > "$tmp/tools-import.log"
verify_installed
echo 'ok: consumer tools and unavailable host probes do not affect import'
# Invalid roots must fail before cleanup, including through a .build symlink.
valid_build_root="$BUILD_ROOT"
mkdir -p "$tmp/external/nginx-1.31.3-asan"
printf 'external sentinel\n' > "$tmp/external/nginx-1.31.3-asan/owned"
for invalid_root in "$tmp/external" "$consumer" "$consumer/../external"; do
    status=0
    BUILD_ROOT="$invalid_root" import_artifact > "$tmp/root-error" 2>&1 || status=$?
    [[ "$status" == 2 ]] || fail "invalid import BUILD_ROOT accepted: $invalid_root (exit $status)"
    grep -Fq 'invalid BUILD_ROOT:' "$tmp/root-error" || fail 'wrong root rejection diagnostic'
    [[ -f "$tmp/external/nginx-1.31.3-asan/owned" ]] || fail 'external sentinel deleted'
done
mv "$BUILD_ROOT" "$consumer/saved-build"
ln -s "$tmp/external" "$BUILD_ROOT"
status=0
import_artifact > "$tmp/root-error" 2>&1 || status=$?
[[ "$status" == 2 ]] || fail "symlink import BUILD_ROOT accepted (exit $status)"
[[ -f "$tmp/external/nginx-1.31.3-asan/owned" ]] || fail 'symlink external sentinel deleted'
rm "$BUILD_ROOT"
mv "$consumer/saved-build" "$BUILD_ROOT"
BUILD_ROOT="$consumer/new/nested-build" import_artifact
[[ -x "$consumer/new/nested-build/nginx-1.31.3-asan/objs/nginx" ]] || fail 'nested root import rejected'
[[ "$BUILD_ROOT" == "$valid_build_root" ]] || fail 'root override escaped function'
echo 'ok: import root containment preserves external sentinels and permits nested roots'
touch "$BUILD_ROOT/nginx-1.31.3-asan/owned"
wrong_digest="$(printf wrong | sha256sum | cut -d' ' -f1)"
EXPECTED_BUILD_IDENTITY="$wrong_digest" expect_failure producer 'ASan artifact producer binding mismatch' import_artifact
EXPECTED_BINARY_SHA256="$wrong_digest" expect_failure digest 'ASan artifact SHA-256 mismatch' import_artifact
EXPECTED_ARTIFACT_IDENTITY="$wrong_digest" expect_failure input-identity 'ASan consumer build identity mismatch' import_artifact
EXPECTED_ARTIFACT_SHA256="$wrong_digest" expect_failure binding 'ASan artifact producer binding mismatch' import_artifact
expect_failure version 'ASan consumer build identity mismatch' \
    bash ci/tools/ci-build-artifact.sh import 1.31.4 "$tmp/artifact"
expect_failure malformed-version 'invalid ASan artifact version' \
    bash ci/tools/ci-build-artifact.sh import '../1.31.3' "$tmp/artifact"
TEST_HARNESS=1 expect_failure harness 'ASan consumer build identity mismatch' import_artifact

for path in src/module.c config .github/versions.env ci/tools/ci-build.sh; do
    cp "$path" "$tmp/saved-source"
    printf '\nchanged input\n' >> "$path"
    expect_failure "source:$path" 'ASan consumer build identity mismatch' import_artifact
    cp "$tmp/saved-source" "$path"
done
mkdir patches
printf 'changed patch\n' > patches/example.patch
expect_failure patch 'ASan consumer build identity mismatch' import_artifact
rm -rf patches

for field in EXPECTED_BUILD_IDENTITY EXPECTED_BINARY_SHA256 EXPECTED_ARTIFACT_IDENTITY EXPECTED_ARTIFACT_SHA256; do
    for value in '' invalid "${wrong_digest:1}" "${wrong_digest}0"; do
        expect_failure "malformed:$field:${#value}" 'missing or malformed ASan producer outputs' \
            env "$field=$value" bash ci/tools/ci-build-artifact.sh import 1.31.3 "$tmp/artifact"
    done
done
mv "$tmp/artifact/nginx" "$tmp/saved-binary"
expect_failure missing 'missing or non-regular ASan artifact' import_artifact
ln -s "$tmp/saved-binary" "$tmp/artifact/nginx"
expect_failure symlink 'missing or non-regular ASan artifact' import_artifact
rm "$tmp/artifact/nginx"
mkdir "$tmp/artifact/nginx"
expect_failure directory 'missing or non-regular ASan artifact' import_artifact
rmdir "$tmp/artifact/nginx"
cp "$tmp/saved-binary" "$tmp/artifact/nginx"
printf 'changed binary\n' >> "$tmp/artifact/nginx"
# Downloaded metadata is attacker controlled and cannot change expected values.
printf 'identity=%s\nsha256=%s\nartifact-identity=%s\nartifact-sha256=%s\n' \
    "$wrong_digest" "$(sha256sum "$tmp/artifact/nginx" | cut -d' ' -f1)" \
    "$EXPECTED_ARTIFACT_IDENTITY" "$wrong_digest" > "$tmp/artifact/manifest"
expect_failure downloaded-manifest 'ASan artifact SHA-256 mismatch' import_artifact
cp "$tmp/saved-binary" "$tmp/artifact/nginx"
import_artifact
verify_installed
[[ ! -e "$BUILD_ROOT/nginx-1.31.3-asan/owned" ]] || fail 'valid import did not replace destination'
echo 'ok: portable ASan artifact controls passed'
