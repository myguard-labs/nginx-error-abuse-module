#!/usr/bin/env bash
#
# Build nginx (or angie) with the error-abuse module, for local dev and CI.
#
#   ci/tools/ci-build.sh [flavor] [version] [mode]
#     flavor : nginx (default) | angie
#     version: pinned source version, e.g. 1.31.3
#     mode   : debug (default, dynamic .so) | asan (static, sanitizers)
#              | module (dynamic .so only, nginx core NOT compiled)
#              | coverage (dynamic .so, gcov-instrumented, -O0)
#              | fault-list-push | fault-retry-buffer
#              | fault-persist-short-read | fault-persist-short-write
#              | fault-persist-fsync | fault-redis-backoff | fault-redis-state
#              | fault-evict-scan-budget
#                (test-only dynamic .so; nginx core NOT compiled)
#
# The built tree lives under ./.build, ONE TREE PER MODE:
#   .build/<dir>-<mode>/objs/nginx                          (server binary)
#   .build/<dir>-<mode>/objs/ngx_http_error_abuse_module.so (dynamic modes)
#
# ---------------------------------------------------------------------------
# CACHING -- and the one trap that makes it dangerous
#
# All modes compile the SAME sources with INCOMPATIBLE flags (asan adds
# -fsanitize=address; coverage adds --coverage; fault modes add their test
# seam; debug does none of those). Sharing one tree across modes and relying
# on `./configure` to rewrite objs/Makefile every run is what made that safe
# WITHOUT caching.
# The moment the build tree itself is cached, that accident becomes a bug: a
# cached debug objs/ restored into an asan job links non-instrumented
# objects and the sanitizer job goes green while checking nothing.
#
# So: the mode is part of the tree path AND part of every cache key. Never
# collapse these trees back into one to "save disk".
#
# Layers, cheapest first:
#   1. apt/packages   -- check-before-install in the calling workflow /
#                        .github/actions/build-cache, not a cache layer here.
#   2. ccache         -- compiler cache; keyed by content
#                        (CCACHE_COMPILERCHECK=content), so it survives a
#                        reconfigure. Wired via --with-cc, NOT the CC env
#                        var: nginx's configure ignores a bare CC=.
#   3. mold           -- faster linker, used when present. SKIPPED under
#                        asan -- the sanitizer runtimes want the default
#                        linker.
#   4. eatmydata      -- wraps ./configure ONLY. configure does tiny
#                        writes+fsyncs (probe files, autoconf.err, Makefile
#                        fragments) that gain nothing from durability --
#                        objs/ is scratch, rebuilt from src/ on any failure.
#                        `make` stays un-wrapped so build outputs retain
#                        normal write semantics.
#   5. source tarball -- digest-verified after every restore/download.
#
# Executable trees require a fresh exact Actions service restore on main from
# a push, schedule or manual run. The action deletes disk state BEFORE restore,
# uses an exact ref/input key without fallback, and forwards its hit and identity
# only to the matching build step. A colocated identity alone grants no trust.
# Other runs extract pinned source anew; ccache reuses compatible compilation.
# Same-run consumers use producer-bound ci-build-artifact.sh artifacts.
#
# Compilation caches are opt-out via NO_CACHE=1, so a job can force a
# from-scratch build without editing this script. Source verification is never
# disabled: both cache hits and fresh downloads must match versions.env.
# ---------------------------------------------------------------------------

set -euo pipefail

MODULE_DIR="$(pwd -P)"
# All cleanup and extraction targets must remain beneath this physical module
# root. Resolve missing suffixes without creating them and reject symlink
# redirection before identity probes, cache preparation, downloads or writes.
root_input="${BUILD_ROOT:-$MODULE_DIR/.build}"
invalid_build_root() {
    echo 'invalid BUILD_ROOT: expected a nonsymlink directory below the module root' >&2
    exit 2
}
if ! ROOT="$(realpath -m -- "$root_input")" \
    || ! root_lexical="$(realpath -ms -- "$root_input")" \
    || [[ "$ROOT" != "$root_lexical" || "$ROOT" != "$MODULE_DIR/"* ]]; then
    invalid_build_root
fi
root_part="$ROOT"
while [[ "$root_part" != "$MODULE_DIR" ]]; do
    [[ ! -L "$root_part" && ( ! -e "$root_part" || -d "$root_part" ) ]] || invalid_build_root
    root_part="${root_part%/*}"
done
NO_CACHE="${NO_CACHE:-0}"
VERSIONS_FILE="$MODULE_DIR/.github/versions.env"

if [[ ! -f "$VERSIONS_FILE" ]]; then
    echo "version pin file not found: $VERSIONS_FILE" >&2
    exit 2
fi
# Path is rooted at the required repository cwd.
# shellcheck disable=SC1090,SC1091
source "$VERSIONS_FILE"

FLAVOR="${1:-nginx}"
VERSION="${2:-$NGINX_VERSION}"
MODE="${3:-debug}"
EXPECTED_SHA256=""

case "$MODE" in
    debug|asan|module|coverage \
        |fault-list-push|fault-retry-buffer \
        |fault-persist-short-read|fault-persist-short-write \
        |fault-persist-fsync|fault-redis-backoff|fault-redis-state \
        |fault-evict-scan-budget)
        ;;
    *)
        echo "unsupported mode: $MODE" >&2
        exit 2
        ;;
esac

add_matching_pin() {
    local name="$1"
    local pinned_version="$2"
    local pinned_sha256="$3"

    if [[ "$VERSION" != "$pinned_version" ]]; then
        return
    fi
    if [[ -n "$EXPECTED_SHA256" && "$EXPECTED_SHA256" != "$pinned_sha256" ]]; then
        echo "conflicting SHA-256 pins for $FLAVOR $VERSION ($name)" >&2
        exit 2
    fi
    EXPECTED_SHA256="$pinned_sha256"
}

case "$FLAVOR" in
    nginx)
        add_matching_pin NGINX_MAINLINE \
            "${NGINX_MAINLINE:?missing NGINX_MAINLINE in $VERSIONS_FILE}" \
            "${NGINX_MAINLINE_SHA256:?missing NGINX_MAINLINE_SHA256 in $VERSIONS_FILE}"
        add_matching_pin NGINX_STABLE \
            "${NGINX_STABLE:?missing NGINX_STABLE in $VERSIONS_FILE}" \
            "${NGINX_STABLE_SHA256:?missing NGINX_STABLE_SHA256 in $VERSIONS_FILE}"
        add_matching_pin NGINX_VERSION \
            "${NGINX_VERSION:?missing NGINX_VERSION in $VERSIONS_FILE}" \
            "${NGINX_VERSION_SHA256:?missing NGINX_VERSION_SHA256 in $VERSIONS_FILE}"
        URL="https://nginx.org/download/nginx-${VERSION}.tar.gz"
        TARBALL_DIR="nginx-${VERSION}"
        BINARY="nginx"
        ;;
    angie)
        add_matching_pin ANGIE_VERSION \
            "${ANGIE_VERSION:?missing ANGIE_VERSION in $VERSIONS_FILE}" \
            "${ANGIE_SHA256:?missing ANGIE_SHA256 in $VERSIONS_FILE}"
        URL="https://download.angie.software/files/angie-${VERSION}.tar.gz"
        TARBALL_DIR="angie-${VERSION}"
        BINARY="angie"
        ;;
    *)
        echo "unsupported flavor: $FLAVOR" >&2
        exit 2
        ;;
esac

if [[ -z "$EXPECTED_SHA256" ]]; then
    echo "no SHA-256 pin for $FLAVOR $VERSION in $VERSIONS_FILE" >&2
    exit 2
fi
if [[ ! "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "invalid SHA-256 pin for $FLAVOR $VERSION in $VERSIONS_FILE" >&2
    exit 2
fi

# The mode is in the tree path -- see the CACHING block above. Sharing one
# tree across modes is what lets a cached debug objs/ silently disarm the
# asan/coverage job, so every mode (not just coverage) gets its own dir.
# TEST_HARNESS=1 gets its own suffix for the same reason: it is an ADDITIVE
# flag on top of any mode (see the CC_OPT append below), not a mode of its
# own. Without a distinct suffix a harness-enabled debug tree and a plain
# debug tree would overwrite each other's outputs. The exact build identity
# below also includes this flag and the resulting configure arguments.
DIR="${TARBALL_DIR}-${MODE}"
if [ "${TEST_HARNESS:-0}" = "1" ]; then
    DIR="${DIR}-harness"
fi

CC_OPT="-DNGX_DEBUG_PALLOC=1 -g3 -O0 -fno-omit-frame-pointer -funwind-tables"
LD_OPT=""
ADD_MODULE="--add-dynamic-module=$MODULE_DIR"
if [ "$MODE" = "asan" ]; then
    # Disable the UBSan sub-checks that nginx CORE trips as benign false
    # positives so a soak/runtime under sanitizers doesn't abort on them:
    #   function          - core calls body/trailers filters through a generic
    #                        ngx_*_filter_pt whose prototype differs slightly
    #                        (ngx_output_chain -> ngx_http_trailers_filter).
    #   nonnull-attribute - core passes NULL + len 0 to memcpy in the proxy/
    #                        upstream path (ngx_http_proxy_create_request).
    #   pointer-overflow  - core does p +/- n pointer arithmetic that UBSan
    #                        flags on some buffers.
    # ASan (the high-value memory checker) and the rest of UBSan stay on.
    # These -fno-sanitize sub-check names are clang-specific; gcc's configure
    # rejects nonnull-attribute/pointer-overflow. Only add them under clang
    # (the local soak/stress path); gcc keeps plain -fsanitize (CI was green and
    # gcc does not trip these core FPs the same way).
    SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
    if "${CC:-cc}" --version 2>/dev/null | grep -qi clang; then
        SAN="-fsanitize=address,undefined -fno-sanitize=function,nonnull-attribute,pointer-overflow -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
    fi
    CC_OPT="$SAN"
    LD_OPT="$SAN"
    ADD_MODULE="--add-module=$MODULE_DIR"
elif [ "$MODE" = "coverage" ]; then
    # gcov instrumentation. Static (--add-module), not dynamic: gcov attaches
    # its counters at compile time either way, but keeping this mode's build
    # shape close to asan's (also static) means one fewer configure variant to
    # reason about. -O0 so line numbers in the .gcno map exactly to source
    # lines; -O1+ coverage reports can attribute hits to the wrong line after
    # the optimizer merges blocks.
    CC_OPT="--coverage -g -O0 -fno-omit-frame-pointer"
    LD_OPT="--coverage"
    ADD_MODULE="--add-module=$MODULE_DIR"
elif [ "$MODE" = "fault-list-push" ]; then
    CC_OPT="$CC_OPT -DNGX_HTTP_ERROR_ABUSE_TEST_FAIL_REJECT_HEADER_PUSH=1"
elif [ "$MODE" = "fault-retry-buffer" ]; then
    CC_OPT="$CC_OPT -DNGX_HTTP_ERROR_ABUSE_TEST_FAIL_RETRY_AFTER_ALLOC=1"
elif [ "$MODE" = "fault-persist-short-read" ]; then
    CC_OPT="$CC_OPT -DNGX_HTTP_ERROR_ABUSE_TEST_SHORT_READ=1"
elif [ "$MODE" = "fault-persist-short-write" ]; then
    CC_OPT="$CC_OPT -DNGX_HTTP_ERROR_ABUSE_TEST_SHORT_WRITE=1"
elif [ "$MODE" = "fault-persist-fsync" ]; then
    CC_OPT="$CC_OPT -DNGX_HTTP_ERROR_ABUSE_TEST_FAIL_PERSIST_FSYNC=1"
elif [ "$MODE" = "fault-redis-backoff" ]; then
    CC_OPT="$CC_OPT -DNGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT=10 -DNGX_HTTP_ERROR_ABUSE_REDIS_RECONNECT_MAX=80 -DNGX_HTTP_ERROR_ABUSE_TEST_REDIS_BACKOFF_CAP=1 -DNGX_HTTP_ERROR_ABUSE_TEST_REDIS_BACKOFF_TRACE=1"
elif [ "$MODE" = "fault-redis-state" ]; then
    CC_OPT="$CC_OPT -DNGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_THRESHOLD=2 -DNGX_HTTP_ERROR_ABUSE_REDIS_CIRCUIT_BREAKER_DURATION=2"
elif [ "$MODE" = "fault-evict-scan-budget" ]; then
    CC_OPT="$CC_OPT -DNGX_HTTP_ERROR_ABUSE_EVICT_SCAN_LIMIT=1"
fi

# TEST_HARNESS=1 compiles in the probe endpoint and the slab fault injector
# (NGX_TEST_HARNESS, see src/ngx_http_error_abuse_probe_hooks.c) so
# ci/t/prober/run.sh's error_abuse_probe directive exists in the built
# binary. Additive across every mode above, not a mode of its own: the
# prober needs to run against debug, coverage and asan trees alike, and each
# already has its own tree path (see the CACHING block), so the flag folds
# into whichever CC_OPT that mode picked rather than adding a fourth axis to
# the mode enum.
if [ "${TEST_HARNESS:-0}" = "1" ]; then
    CC_OPT="$CC_OPT -DNGX_TEST_HARNESS=1"
fi

# --- ccache -------------------------------------------------------------
# nginx's configure IGNORES a bare `CC=` env var, so `CC="ccache cc"` would
# silently do nothing -- it must go through --with-cc, same as $CC honouring
# below. Skipped when $CC is unset AND ccache is absent, so a plain `cc`
# build stays identical to before this layer existed.
BASE_CC="${CC:-cc}"
WITH_CC="$BASE_CC"
if [ "$NO_CACHE" != "1" ] && command -v ccache >/dev/null 2>&1; then
    WITH_CC="ccache $BASE_CC"
    # Compiler identity is content-hashed, so a toolchain bump invalidates
    # correctly on its own; no manual key bumping needed. Sanitizer/coverage
    # flags are part of CC_OPT/LD_OPT, which ccache also hashes, so an asan
    # object can never be served to a debug build (or vice versa) -- belt and
    # braces alongside the per-mode tree.
fi
# --- mold ---------------------------------------------------------------
# Skipped under asan: the sanitizer runtimes want the default linker.
if [ "$NO_CACHE" != "1" ] && [ "$MODE" != "asan" ] \
   && command -v mold >/dev/null 2>&1; then
    LD_OPT="$LD_OPT -fuse-ld=mold"
fi

CONF_ARGS="--with-compat --with-debug --with-threads --with-http_realip_module --with-cc=${WITH_CC} --with-cc-opt=${CC_OPT} --with-ld-opt=${LD_OPT} ${ADD_MODULE}"
BUILD_IDENTITY="$(bash "$MODULE_DIR/ci/tools/build-identity.sh" "$BASE_CC" \
    "$FLAVOR" "$VERSION" "$EXPECTED_SHA256" "$MODE" "${TEST_HARNESS:-0}" "$CONF_ARGS")"
if [[ "${CI_BUILD_IDENTITY_ONLY:-0}" == "1" ]]; then
    printf '%s\n' "$BUILD_IDENTITY"
    exit 0
fi

# This phase runs before the Actions cache lookup, even when restore is denied.
# It cannot preserve a forged tree left behind by a persistent runner's old job.
if [[ "${CI_BUILD_CACHE_PREPARE_ONLY:-0}" == "1" ]]; then
    rm -rf "${ROOT:?}/${DIR:?}"
    printf 'tree=%s\n' "$ROOT/$DIR" >> "${GITHUB_OUTPUT:?missing GITHUB_OUTPUT}"
    printf '%s\n' "$BUILD_IDENTITY"
    exit 0
fi

# Match the action's explicit producer allowlist. PR/PR-target runs, tags and
# non-main refs may never execute a cross-run tree, even with a claimed hit.
TRUSTED_CACHE=0
case "${GITHUB_EVENT_NAME:-}:${GITHUB_REF:-}" in
    push:refs/heads/main|schedule:refs/heads/main|workflow_dispatch:refs/heads/main)
        TRUSTED_CACHE=1 ;;
esac
if [[ "$NO_CACHE" != "1" && "$TRUSTED_CACHE" == "1" \
    && "${CI_BUILD_CACHE_HIT:-}" == "true" \
    && "$(bash "$MODULE_DIR/ci/tools/build-identity.sh" --executable-cache-eligible)" == true \
    && "${CI_BUILD_CACHE_IDENTITY:-}" == "$BUILD_IDENTITY" \
    && -f "$ROOT/$DIR/.build-identity" && ! -L "$ROOT/$DIR/.build-identity" \
    && "$(cat "$ROOT/$DIR/.build-identity")" == "$BUILD_IDENTITY" \
    && -f "$ROOT/$DIR/configure" && -f "$ROOT/$DIR/objs/Makefile" ]]; then
    complete=1
    if [[ "$MODE" != "asan" && "$MODE" != "coverage" ]]; then
        output="$ROOT/$DIR/objs/ngx_http_error_abuse_module.so"
        [[ -s "$output" && ! -L "$output" ]] || complete=0
    fi
    case "$MODE" in
        debug|asan|coverage)
            output="$ROOT/$DIR/objs/$BINARY"
            [[ -s "$output" && -x "$output" && ! -L "$output" ]] || complete=0 ;;
    esac
    if [[ "$complete" == "1" ]]; then
        printf 'build-cache: trusted exact service hit; reuse %s (identity=%s)\n' "$ROOT/$DIR" "$BUILD_IDENTITY"
        exit 0
    fi
fi
echo 'build-cache: rebuild (no eligible exact service hit with complete matching identity)'

if [[ "$NO_CACHE" != "1" ]] && command -v ccache >/dev/null 2>&1; then
    export CCACHE_DIR="${CCACHE_DIR:-$HOME/.cache/ccache}"
    export CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-2G}"
    export CCACHE_COMPILERCHECK=content
    ccache --set-config=max_size="$CCACHE_MAXSIZE" 2>/dev/null || true
fi

mkdir -p "$ROOT"
# Source archives are verified before extraction. Rejected executable trees
# are discarded regardless of stamps, including on persistent runners.
if [[ "$NO_CACHE" == "1" ]]; then
    rm -f "$ROOT/${TARBALL_DIR}.tar.gz"
fi
bash "$MODULE_DIR/.github/scripts/fetch-verify.sh" \
    "$URL" "$EXPECTED_SHA256" "$ROOT/${TARBALL_DIR}.tar.gz"
rm -rf "${ROOT:?}/${DIR:?}"
tar -xzf "$ROOT/${TARBALL_DIR}.tar.gz" -C "$ROOT" --transform "s/^${TARBALL_DIR}/${DIR}/"
cd "$ROOT/$DIR"

# --- eatmydata ------------------------------------------------------------
# Wraps ./configure ONLY -- see the CACHING block header for why `make` and
# everything outside this script (tarball fetch, apt-get) stay un-wrapped.
# Skipped under asan: eatmydata works by LD_PRELOAD-ing libeatmydata.so, and
# every one of configure's probe binaries is ASan-instrumented in asan mode,
# so they abort at startup unless the ASan runtime loads first --
# "ASan runtime does not come first in initial library list" reads as a
# configure failure, not the LD_PRELOAD ordering bug it actually is.
EATMYDATA=""
if [ "$NO_CACHE" != "1" ] && [ "$MODE" != "asan" ] \
   && command -v eatmydata >/dev/null 2>&1; then
    EATMYDATA="eatmydata"
fi

# shellcheck disable=SC2086
$EATMYDATA ./configure \
    --with-compat \
    --with-debug \
    --with-threads \
    --with-http_realip_module \
    --with-cc="$WITH_CC" \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

if [ "$MODE" != "asan" ] && [ "$MODE" != "coverage" ]; then
    make -j"$(nproc)" modules
fi

if [ "$MODE" != "module" ] && [ "$MODE" != "fault-list-push" ] \
   && [ "$MODE" != "fault-retry-buffer" ] \
   && [ "$MODE" != "fault-persist-short-read" ] \
   && [ "$MODE" != "fault-persist-short-write" ] \
   && [ "$MODE" != "fault-persist-fsync" ] \
   && [ "$MODE" != "fault-redis-backoff" ] \
   && [ "$MODE" != "fault-redis-state" ] \
   && [ "$MODE" != "fault-evict-scan-budget" ]; then
    make -j"$(nproc)"
    printf 'binary=%s\n' "$ROOT/$DIR/objs/$BINARY"
fi

# Static builds (asan, coverage: --add-module) compile the module INTO the
# binary above; there is no separate objs/*.so to report.
if [ "$MODE" != "asan" ] && [ "$MODE" != "coverage" ]; then
    printf 'module=%s\n' "$ROOT/$DIR/objs/ngx_http_error_abuse_module.so"
fi

# A cache that silently stops hitting is worse than no cache: you keep paying
# for it (keys, restore steps, disk) and get nothing back. Print the hit rate
# so a regression is visible in the job log instead of invisible.
if [ "$NO_CACHE" != "1" ] && command -v ccache >/dev/null 2>&1; then
    echo "--- ccache"
    ccache --show-stats 2>/dev/null | grep -Ei 'hits|misses|cache size' || true
fi

# Publish only after every requested make target succeeded.
printf '%s\n' "$BUILD_IDENTITY" > .build-identity
