#!/usr/bin/env bash
# Exercise real build/artifact scripts with a tiny pinned source and fake make.
# No network, compilation, package installation or runner cache is needed.
set -euo pipefail
repo="$(git rev-parse --show-toplevel)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/ci-build-cache.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/repo/ci/tools" "$tmp/repo/.github/scripts" "$tmp/repo/src" \
    "$tmp/bin" "$tmp/source/nginx-1.31.3"
cp "$repo/ci/tools/"{ci-build,build-identity,ci-build-artifact}.sh "$tmp/repo/ci/tools/"
cp "$repo/.github/scripts/fetch-verify.sh" "$tmp/repo/.github/scripts/"
printf 'NGINX_MAINLINE=1.31.3\nNGINX_MAINLINE_SHA256=%s\nNGINX_STABLE=1.30.4\nNGINX_STABLE_SHA256=%s\nNGINX_VERSION=1.31.3\nNGINX_VERSION_SHA256=%s\n' \
    "$(printf 'cache fixture pin' | sha256sum | cut -d' ' -f1)" \
    "$(printf 'stable fixture pin' | sha256sum | cut -d' ' -f1)" \
    "$(printf 'cache fixture pin' | sha256sum | cut -d' ' -f1)" > "$tmp/repo/.github/versions.env"
: > "$tmp/repo/config"
echo source-v1 > "$tmp/repo/src/module.c"
mkdir -p "$tmp/repo/ci/t/harness/src"
for file in ngx_test_probe.c ngx_test_probe_arm.c ngx_test_probe.h; do
    printf 'harness fixture\n' > "$tmp/repo/ci/t/harness/src/$file"
done
cat > "$tmp/source/nginx-1.31.3/configure" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo configure >> "$OPERATIONS"
mkdir -p objs
: > objs/Makefile
SH
chmod +x "$tmp/source/nginx-1.31.3/configure"
tar -czf "$tmp/source.tar.gz" -C "$tmp/source" nginx-1.31.3
digest="$(sha256sum "$tmp/source.tar.gz" | cut -d' ' -f1)"
sed -i -E "s/^(NGINX_MAINLINE_SHA256|NGINX_VERSION_SHA256)=.*/\1=$digest/" "$tmp/repo/.github/versions.env"
cp "$tmp/repo/.github/versions.env" "$tmp/valid-versions.env"
cat > "$tmp/bin/make" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo make >> "$OPERATIONS"
printf '#!/bin/sh\necho fresh-asan-binary\n' > objs/nginx
chmod +x objs/nginx
printf 'fresh-dynamic-module\n' > objs/ngx_http_error_abuse_module.so
if [[ -n "${GCC_EXEC_PREFIX:-}" && -f "${GCC_EXEC_PREFIX}cc1" ]]; then
    cp "${GCC_EXEC_PREFIX}cc1" objs/fixture-toolchain
else
    printf 'default-toolchain\n' > objs/fixture-toolchain
fi
SH
cat > "$tmp/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo fetch >> "$OPERATIONS"
while [[ "$1" != '-o' ]]; do shift; done
cp "$FIXTURE_ARCHIVE" "$2"
SH
# Ensure deterministic flags without using a real ccache or host cache dirs.
printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/ccache"
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:/usr/bin:/bin"
export OPERATIONS="$tmp/operations" FIXTURE_ARCHIVE="$tmp/source.tar.gz"
export GITHUB_OUTPUT="$tmp/outputs"
# Keep inherited runner build roots out of this disposable fixture.
export BUILD_ROOT="$tmp/repo/.build"
toolchain_overrides=(GCC_EXEC_PREFIX COMPILER_PATH LIBRARY_PATH CPATH
    C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH)
consumer_overrides=(NGX_ERROR_ABUSE_INCS NGX_ERROR_ABUSE_LIBS)
cache_overrides=("${toolchain_overrides[@]}" "${consumer_overrides[@]}")
unset "${cache_overrides[@]}"
cd "$tmp/repo"

fail() { echo "FAIL: $*" >&2; exit 1; }
expect_failure() {
    local message="$1"
    shift
    if "$@" > "$tmp/error" 2>&1; then fail "expected failure: $message"; fi
    grep -Fq "$message" "$tmp/error" || { cat "$tmp/error" >&2; fail "wrong failure: $message"; }
    printf 'ok: %s\n' "$message"
}
identity() { CI_BUILD_IDENTITY_ONLY=1 bash ci/tools/ci-build.sh nginx 1.31.3 "${1:-asan}"; }
import_artifact() { bash ci/tools/ci-build-artifact.sh import 1.31.3 "$tmp/artifact"; }
changed() { [[ "$1" != "$2" ]] || fail "identity did not change: $3"; }

sed -i -E 's/^(NGINX_MAINLINE_SHA256|NGINX_VERSION_SHA256)=.*/\1=malformed/' .github/versions.env
if identity > "$tmp/pin-error" 2>&1; then fail 'malformed fixture pin unexpectedly succeeded'; fi
grep -Fq 'invalid SHA-256 pin for nginx 1.31.3' "$tmp/pin-error" || {
    cat "$tmp/pin-error" >&2
    fail 'malformed fixture pin had the wrong diagnostic'
}
[[ ! -e .build && ! -e "$OPERATIONS" ]] || fail 'malformed fixture pin admitted build work'
cp "$tmp/valid-versions.env" .github/versions.env

# Hide only dpkg-query; all other host tools and fixture commands remain usable.
mkdir "$tmp/no-dpkg"
for tool in /usr/bin/*; do
    [[ "${tool##*/}" == dpkg-query ]] && continue
    ln -s "$tool" "$tmp/no-dpkg/${tool##*/}"
done
for tool in "$tmp/bin/"*; do
    ln -sf "$tool" "$tmp/no-dpkg/${tool##*/}"
done
missing_dpkg='build-identity: dpkg-query is required; install Debian dpkg tooling and ensure dpkg-query is on PATH'
failed_dpkg='build-identity: dpkg-query failed; verify the Debian package database is readable'
expect_package_failure() {
    local probe_path="$1" message="$2" operations_before=''
    shift 2
    if [[ -e "$OPERATIONS" ]]; then operations_before="$(cat "$OPERATIONS")"; fi
    PATH="$probe_path" expect_failure "$message" "$@"
    if grep -Eq 'command not found|build-cache: trusted exact service hit; reuse|^[0-9a-f]{64}$' "$tmp/error"; then
        fail 'package probe emitted command-not-found, identity or executable cache hit'
    fi
    [[ "$(cat "$OPERATIONS" 2>/dev/null || true)" == "$operations_before" ]] || fail 'package probe fetched/configured/built'
}
expect_package_failure "$tmp/no-dpkg" "$missing_dpkg" identity
NO_CACHE=1 expect_package_failure "$tmp/no-dpkg" "$missing_dpkg" identity
NO_CACHE=1 expect_package_failure "$tmp/no-dpkg" "$missing_dpkg" bash ci/tools/ci-build.sh nginx 1.31.3 asan
[[ ! -e .build ]] || fail 'missing dpkg-query created a build tree'

before="$(identity)"
[[ "$before" =~ ^[0-9a-f]{64}$ ]] || fail 'invalid build identity'
[[ ! -e .build && ! -e "$OPERATIONS" ]] || fail 'identity probe built or fetched'
[[ "$before" == "$(identity)" ]] || fail 'identity is nondeterministic'
[[ "$(bash ci/tools/build-identity.sh --executable-cache-eligible)" == true ]] || fail 'default toolchain ineligible'
portable="$(bash ci/tools/build-identity.sh --portable-asan 1.31.3)"
for override in "${toolchain_overrides[@]}"; do
    export "$override=$tmp/toolchain with spaces/"
    changed "$before" "$(identity)" "$override"
    export "$override="
    changed "$before" "$(identity)" "empty-$override"
    unset "$override"
done
for override in "${cache_overrides[@]}"; do
    export "$override=$tmp/toolchain with spaces/"
    [[ "$(bash ci/tools/build-identity.sh --executable-cache-eligible)" == false ]] || fail "override eligible: $override"
    [[ "$(bash ci/tools/build-identity.sh --portable-asan 1.31.3)" == "$portable" ]] || fail "override changed portable identity: $override"
    export "$override="
    [[ "$(bash ci/tools/build-identity.sh --executable-cache-eligible)" == false ]] || fail "empty override eligible: $override"
    [[ "$(bash ci/tools/build-identity.sh --portable-asan 1.31.3)" == "$portable" ]] || fail "empty override changed portable identity: $override"
    unset "$override"
done
echo 'ok: set and empty search/consumer overrides disable reuse without contaminating portable inputs'
changed "$before" "$(identity debug)" mode
harness_full="$(TEST_HARNESS=1 identity)"
harness_portable="$(TEST_HARNESS=1 bash ci/tools/build-identity.sh --portable-asan 1.31.3)"
for file in ci/t/harness/src/ngx_test_probe.c ci/t/harness/src/ngx_test_probe_arm.c ci/t/harness/src/ngx_test_probe.h; do
    cp "$file" "$tmp/harness-saved"
    printf 'changed\n' >> "$file"
    changed "$harness_full" "$(TEST_HARNESS=1 identity)" "harness:$file"
    changed "$harness_portable" "$(TEST_HARNESS=1 bash ci/tools/build-identity.sh --portable-asan 1.31.3)" "portable-harness:$file"
    [[ "$before" == "$(identity)" ]] || fail "disabled harness affected identity: $file"
    cp "$tmp/harness-saved" "$file"
done
mv ci/t/harness/src/ngx_test_probe.h "$tmp/harness-header"
if TEST_HARNESS=1 identity > "$tmp/missing-harness" 2>&1; then fail 'missing harness accepted'; fi
if TEST_HARNESS=1 bash ci/tools/build-identity.sh --portable-asan 1.31.3 > "$tmp/missing-harness" 2>&1; then fail 'missing portable harness accepted'; fi
mv "$tmp/harness-header" ci/t/harness/src/ngx_test_probe.h
changed "$before" "$(TEST_HARNESS=1 identity)" harness
changed "$before" "$(CFLAGS=-DCHANGED identity)" environment-flags
echo source-v2 >> src/module.c
changed "$before" "$(identity)" source
sed -i '$d' src/module.c
mkdir patches
echo patch > patches/change.patch
changed "$before" "$(identity)" patch
rm -rf patches
echo '# pin revision' >> .github/versions.env
changed "$before" "$(identity)" pins
sed -i '$d' .github/versions.env
cp "$(command -v cc)" "$tmp/bin/other-cc"
changed "$before" "$(CC=other-cc identity)" compiler-path
# Probe platform and installed dependency differences without changing the host.
printf '#!/bin/sh\necho other-arch\n' > "$tmp/bin/uname"
chmod +x "$tmp/bin/uname"
changed "$before" "$(identity)" architecture
rm "$tmp/bin/uname"
printf '#!/bin/sh\necho dependency=changed:arch\n' > "$tmp/bin/dpkg-query"
chmod +x "$tmp/bin/dpkg-query"
changed "$before" "$(identity)" dependencies
rm "$tmp/bin/dpkg-query"
printf '#!/bin/sh\necho partial-package-output\necho dependency-query-failed >&2\nexit 2\n' > "$tmp/bin/dpkg-query"
chmod +x "$tmp/bin/dpkg-query"
expect_package_failure "$PATH" "$failed_dpkg" identity
NO_CACHE=1 expect_package_failure "$PATH" "$failed_dpkg" bash ci/tools/ci-build.sh nginx 1.31.3 asan
rm "$tmp/bin/dpkg-query"
echo 'ok: deterministic identity and source/patch/pin/compiler/arch/dependency/config isolation'

bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/cold.out"
[[ "$(cat "$OPERATIONS")" == $'fetch\nconfigure\nmake' ]] || fail 'cold build did not fetch/configure/build'
bash ci/tools/ci-build-artifact.sh export 1.31.3 "$tmp/artifact"
export EXPECTED_BUILD_IDENTITY EXPECTED_BINARY_SHA256
export EXPECTED_ARTIFACT_IDENTITY EXPECTED_ARTIFACT_SHA256
EXPECTED_BUILD_IDENTITY="$(sed -n 's/^identity=//p' "$GITHUB_OUTPUT")"
EXPECTED_BINARY_SHA256="$(sed -n 's/^sha256=//p' "$GITHUB_OUTPUT")"
EXPECTED_ARTIFACT_IDENTITY="$(sed -n 's/^artifact-identity=//p' "$GITHUB_OUTPUT")"
EXPECTED_ARTIFACT_SHA256="$(sed -n 's/^artifact-sha256=//p' "$GITHUB_OUTPUT")"
saved_identity="$EXPECTED_BUILD_IDENTITY"
saved_digest="$EXPECTED_BINARY_SHA256"
TEST_HARNESS=1 expect_failure 'ASan producer build identity mismatch' \
    bash ci/tools/ci-build-artifact.sh export 1.31.3 "$tmp/rejected-artifact"
# Consumer starts without any tree or archive; it must still avoid all three
# operations. The output marker proves the producer artifact actually ran.
rm -rf .build
cp "$OPERATIONS" "$tmp/cold-operations"
import_artifact
cmp "$OPERATIONS" "$tmp/cold-operations" || fail 'artifact consumer rebuilt'
[[ "$(.build/nginx-1.31.3-asan/objs/nginx)" == fresh-asan-binary ]] || fail 'wrong artifact installed'
echo 'ok: cold producer and warm artifact consumer (zero fetch/configure/make)'

EXPECTED_BUILD_IDENTITY="$(identity debug)" expect_failure 'ASan artifact producer binding mismatch' import_artifact
TEST_HARNESS=1 expect_failure 'ASan consumer build identity mismatch' import_artifact
echo stale >> src/module.c
expect_failure 'ASan consumer build identity mismatch' import_artifact
sed -i '$d' src/module.c
EXPECTED_BUILD_IDENTITY='' expect_failure 'missing or malformed ASan producer outputs' import_artifact
EXPECTED_BINARY_SHA256=invalid expect_failure 'missing or malformed ASan producer outputs' import_artifact
mv "$tmp/artifact/nginx" "$tmp/saved-binary"
expect_failure 'missing or non-regular ASan artifact' import_artifact
ln -s "$tmp/saved-binary" "$tmp/artifact/nginx"
expect_failure 'missing or non-regular ASan artifact' import_artifact
rm "$tmp/artifact/nginx"
cp "$tmp/saved-binary" "$tmp/artifact/nginx"
echo untrusted >> "$tmp/artifact/nginx"
# An attacker-controlled file beside the artifact cannot override job outputs.
sha256sum "$tmp/artifact/nginx" > "$tmp/artifact/seal"
expect_failure 'ASan artifact SHA-256 mismatch' import_artifact
cp "$tmp/saved-binary" "$tmp/artifact/nginx"
import_artifact
[[ "$EXPECTED_BUILD_IDENTITY" == "$saved_identity" && "$EXPECTED_BINARY_SHA256" == "$saved_digest" ]]

# Forge a matching configure stamp AND identity beside a malicious persistent
# executable tree. Rebuild must extract pinned source, never execute configure
# from the old tree; the verified tarball avoids a second fetch.
bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/warm-source.out"
echo 'echo untrusted-configure >&2; exit 91' > .build/nginx-1.31.3-asan/configure
echo "$saved_identity" > .build/nginx-1.31.3-asan/.build-identity
echo identical-flags > .build/nginx-1.31.3-asan/objs/.conf-stamp
: > .build/nginx-1.31.3-asan/objs/UNTRUSTED_OBJECT
echo 'echo untrusted-binary' > .build/nginx-1.31.3-asan/objs/nginx
cp "$OPERATIONS" "$tmp/before-rebuild"
bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/rebuild.out"
[[ "$(tail -2 "$OPERATIONS")" == $'configure\nmake' ]] || fail 'persistent tree did not rebuild'
[[ "$(wc -l < "$OPERATIONS")" == 8 ]] || fail 'warm source fetched or build was skipped'
[[ "$(.build/nginx-1.31.3-asan/objs/nginx)" == fresh-asan-binary ]] || fail 'untrusted tree survived'
[[ ! -e .build/nginx-1.31.3-asan/objs/UNTRUSTED_OBJECT ]] || fail 'untrusted object survived'
echo 'ok: untrusted persistent tree rebuilt; verified source archive reused'

# Model the Actions service separately from disk state. Local controls cannot
# authenticate that service; the workflow policy test enforces its trust scope.
tree=.build/nginx-1.31.3-asan
cp -a "$tree" "$tmp/service-tree"
export GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main
export CI_BUILD_CACHE_HIT=true CI_BUILD_CACHE_IDENTITY="$saved_identity"
prepare_restore() {
    CI_BUILD_CACHE_PREPARE_ONLY=1 bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/prepare-identity"
    [[ ! -e "$tree" ]] || fail 'prepare did not remove old disk tree before restore'
    [[ "$(cat "$tmp/prepare-identity")" == "$saved_identity" ]] || fail 'prepare identity differs'
    cp -a "$tmp/service-tree" "$tree"
}
expect_rebuild() {
    local label="$1" count
    count="$(wc -l < "$OPERATIONS")"
    bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/cache-build.out"
    [[ "$(tail -2 "$OPERATIONS")" == $'configure\nmake' ]] || fail "no configure/make: $label"
    [[ "$(wc -l < "$OPERATIONS")" == "$((count + 2))" ]] || fail "rebuild skipped or fetched: $label"
    grep -Fq 'build-cache: rebuild' "$tmp/cache-build.out" || fail "missing rebuild reason: $label"
    [[ "$("$tree/objs/nginx")" == fresh-asan-binary ]] || fail "untrusted tree survived: $label"
    echo "ok: rebuild $label"
}
for event in push schedule workflow_dispatch; do
    # Forged disk state cannot survive prepare, even when it claims our identity.
    echo 'echo untrusted-configure >&2; exit 91' > "$tree/configure"
    : > "$tree/objs/UNTRUSTED_OBJECT"
    prepare_restore
    cp "$OPERATIONS" "$tmp/before-hit"
    GITHUB_EVENT_NAME="$event" bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/hit.out"
    cmp "$OPERATIONS" "$tmp/before-hit" || fail 'trusted exact hit rebuilt or fetched'
    grep -Fq 'build-cache: trusted exact service hit; reuse' "$tmp/hit.out" || fail 'missing exact-hit marker'
    [[ ! -e "$tree/objs/UNTRUSTED_OBJECT" ]] || fail 'old disk object survived prepare'
    [[ "$("$tree/objs/nginx")" == fresh-asan-binary ]] || fail 'wrong restored binary'
    echo "ok: trusted fresh exact hit $event (zero fetch/configure/make)"
done
# Reject both a stale advertised identity and a matching identity under an
# override. Mutable directory contents cannot be proven by hashing path text.
mkdir -p "$tmp/toolchain with spaces"
printf 'toolchain-v1\n' > "$tmp/toolchain with spaces/cc1"
for override in "${cache_overrides[@]}"; do
    prepare_restore
    export "$override=$tmp/toolchain with spaces/"
    expect_rebuild "$override-drift"
    CI_BUILD_CACHE_IDENTITY="$(identity)"
    expect_rebuild "$override-matching-identity"
    unset "$override"
    CI_BUILD_CACHE_IDENTITY="$saved_identity"
done
prepare_restore
export GCC_EXEC_PREFIX="$tmp/toolchain with spaces/"
expect_rebuild GCC_EXEC_PREFIX-content-prime
[[ "$(cat "$tree/objs/fixture-toolchain")" == toolchain-v1 ]] || fail 'toolchain prime marker missing'
CI_BUILD_CACHE_IDENTITY="$(identity)"
printf 'toolchain-v2-longer\n' > "${GCC_EXEC_PREFIX}cc1"
[[ "$(identity)" == "$CI_BUILD_CACHE_IDENTITY" ]] || fail 'path identity unexpectedly fingerprints directory contents'
expect_rebuild GCC_EXEC_PREFIX-same-path-content-change
[[ "$(cat "$tree/objs/fixture-toolchain")" == toolchain-v2-longer ]] || fail 'stale toolchain content reused'
unset GCC_EXEC_PREFIX
CI_BUILD_CACHE_IDENTITY="$saved_identity"
for prefix in "$tmp/missing-prefix/" ':'; do
    prepare_restore
    GCC_EXEC_PREFIX="$prefix" expect_rebuild GCC_EXEC_PREFIX-nonempty-boundary
done
for override in "${cache_overrides[@]}"; do
    prepare_restore
    export "$override="
    CI_BUILD_CACHE_IDENTITY="$(identity)"
    printf '%s\n' "$CI_BUILD_CACHE_IDENTITY" > "$tree/.build-identity"
    expect_rebuild "empty-$override-matching-identity"
    unset "$override"
    CI_BUILD_CACHE_IDENTITY="$saved_identity"
done
prepare_restore
cp "$OPERATIONS" "$tmp/before-unset-hit"
bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/unset-hit.out"
cmp "$OPERATIONS" "$tmp/before-unset-hit" || fail 'unset overrides disabled exact hit'
grep -Fq 'build-cache: trusted exact service hit; reuse' "$tmp/unset-hit.out" || fail 'unset overrides lost exact hit'
echo 'ok: unset search/consumer overrides preserve trusted exact hit (zero fetch/configure/make)'
# Neither an exact service hit nor artifact export may bypass host identity.
expect_package_failure "$tmp/no-dpkg" "$missing_dpkg" bash ci/tools/ci-build.sh nginx 1.31.3 asan
expect_package_failure "$tmp/no-dpkg" "$missing_dpkg" bash ci/tools/ci-build-artifact.sh export 1.31.3 "$tmp/rejected-artifact"
printf '#!/bin/sh\necho partial-package-output\nexit 2\n' > "$tmp/bin/dpkg-query"
chmod +x "$tmp/bin/dpkg-query"
expect_package_failure "$PATH" "$failed_dpkg" bash ci/tools/ci-build.sh nginx 1.31.3 asan
expect_package_failure "$PATH" "$failed_dpkg" bash ci/tools/ci-build-artifact.sh export 1.31.3 "$tmp/rejected-artifact"
# Producer-bound consumers deliberately avoid probing the consumer host.
PATH="$tmp/no-dpkg" import_artifact
import_artifact
rm "$tmp/bin/dpkg-query"
prepare_restore
CI_BUILD_CACHE_HIT=false expect_rebuild service-miss
prepare_restore
CI_BUILD_CACHE_HIT='' expect_rebuild absent-service-hit
prepare_restore
CI_BUILD_CACHE_HIT=True expect_rebuild malformed-service-hit
prepare_restore
CI_BUILD_CACHE_IDENTITY='' expect_rebuild missing-expected-identity
prepare_restore
CI_BUILD_CACHE_IDENTITY="$(identity debug)" expect_rebuild wrong-variant-identity
prepare_restore
echo stale > "$tree/.build-identity"
expect_rebuild stale-restored-identity
prepare_restore
rm "$tree/.build-identity"
expect_rebuild missing-restored-identity
prepare_restore
mv "$tree/.build-identity" "$tmp/linked-identity"
ln -s "$tmp/linked-identity" "$tree/.build-identity"
expect_rebuild symlink-identity
for missing in configure objs/Makefile objs/nginx; do
    prepare_restore
    rm "$tree/$missing"
    expect_rebuild "partial-tree-$missing"
done
prepare_restore
chmod -x "$tree/objs/nginx"
expect_rebuild non-executable-binary
prepare_restore
mv "$tree/objs/nginx" "$tmp/linked-binary"
ln -s "$tmp/linked-binary" "$tree/objs/nginx"
expect_rebuild symlink-binary
for event in pull_request pull_request_target workflow_run; do
    prepare_restore
    GITHUB_EVENT_NAME="$event" expect_rebuild "untrusted-event-$event"
done
for ref in refs/heads/feature refs/tags/main refs/pull/1/merge ''; do
    prepare_restore
    GITHUB_REF="$ref" expect_rebuild "untrusted-ref-$ref"
done
# A service miss after prepare cannot revive a matching seal on an old tree.
echo 'echo untrusted-configure >&2; exit 91' > "$tree/configure"
CI_BUILD_CACHE_PREPARE_ONLY=1 bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/prepare-identity"
[[ ! -e "$tree" ]] || fail 'forged disk tree survived prepare'
CI_BUILD_CACHE_HIT=false expect_rebuild forged-old-disk-service-miss
# NO_CACHE denies even a complete, matching restored tree.
prepare_restore
NO_CACHE=1 bash ci/tools/ci-build.sh nginx 1.31.3 asan > "$tmp/no-cache.out"
grep -Fq 'build-cache: rebuild' "$tmp/no-cache.out" || fail 'NO_CACHE accepted executable cache'
# Dynamic debug trees require both server and module; module-only builds need
# their module even though no server executable is required by that mode.
for mode in debug module; do
    unset CI_BUILD_CACHE_HIT CI_BUILD_CACHE_IDENTITY
    bash ci/tools/ci-build.sh nginx 1.31.3 "$mode" > "$tmp/dynamic-cold.out"
    dynamic_tree=".build/nginx-1.31.3-$mode"
    dynamic_identity="$(identity "$mode")"
    cp -a "$dynamic_tree" "$tmp/service-$mode"
    CI_BUILD_CACHE_PREPARE_ONLY=1 bash ci/tools/ci-build.sh nginx 1.31.3 "$mode" > "$tmp/prepare-dynamic"
    [[ ! -e "$dynamic_tree" ]] || fail 'dynamic prepare retained disk tree'
    cp -a "$tmp/service-$mode" "$dynamic_tree"
    export CI_BUILD_CACHE_HIT=true CI_BUILD_CACHE_IDENTITY="$dynamic_identity"
    if [[ "$mode" == module ]]; then rm "$dynamic_tree/objs/nginx"; fi
    cp "$OPERATIONS" "$tmp/before-dynamic-hit"
    bash ci/tools/ci-build.sh nginx 1.31.3 "$mode" > "$tmp/dynamic-hit.out"
    cmp "$OPERATIONS" "$tmp/before-dynamic-hit" || fail "dynamic exact hit rebuilt: $mode"
    grep -Fq 'build-cache: trusted exact service hit; reuse' "$tmp/dynamic-hit.out" || fail 'missing dynamic hit marker'
    rm "$dynamic_tree/objs/ngx_http_error_abuse_module.so"
    bash ci/tools/ci-build.sh nginx 1.31.3 "$mode" > "$tmp/dynamic-partial.out"
    grep -Fq 'build-cache: rebuild' "$tmp/dynamic-partial.out" || fail "partial dynamic tree accepted: $mode"
    [[ -s "$dynamic_tree/objs/ngx_http_error_abuse_module.so" ]] || fail 'dynamic module not rebuilt'
    echo "ok: dynamic exact hit and missing module rebuild $mode"
done
unset CI_BUILD_CACHE_HIT CI_BUILD_CACHE_IDENTITY GITHUB_EVENT_NAME GITHUB_REF

printf '#!/bin/sh\necho build-failed >&2\nexit 2\n' > "$tmp/bin/make"
expect_failure 'build-failed' bash ci/tools/ci-build.sh nginx 1.31.3 asan
[[ ! -e .build/nginx-1.31.3-asan/.build-identity ]] || fail 'failed build published identity'
echo 'ok: failed build cannot publish producer identity'
echo 'OK: cache provenance and artifact controls held'
