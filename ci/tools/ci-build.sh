#!/usr/bin/env bash

set -euo pipefail

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.1}"
MODE="${3:-debug}"
ROOT="${BUILD_ROOT:-$PWD/.build}"
MODULE_DIR="$PWD"

case "$FLAVOR" in
    nginx)
        URL="https://nginx.org/download/nginx-${VERSION}.tar.gz"
        TARBALL_DIR="nginx-${VERSION}"
        BINARY="nginx"
        ;;
    angie)
        URL="https://download.angie.software/files/angie-${VERSION}.tar.gz"
        TARBALL_DIR="angie-${VERSION}"
        BINARY="angie"
        ;;
    *)
        echo "unsupported flavor: $FLAVOR" >&2
        exit 2
        ;;
esac

# `coverage` builds into its OWN tree (nginx-<ver>-coverage), never into the
# same nginx-<ver> dir the debug/asan/module modes share. A gcov-instrumented
# build is configured with different --with-cc-opt flags; reusing the debug
# tree would either recompile in place over a cached non-instrumented build
# (fine only if configure/make correctly detects the flag change every time,
# which is not something to bet a coverage report's correctness on) or, worse,
# skip recompilation and leave stale non-instrumented objects -- producing a
# report that silently reads 0% and looks exactly like a real finding.
if [ "$MODE" = "coverage" ]; then
    DIR="${TARBALL_DIR}-coverage"
else
    DIR="$TARBALL_DIR"
fi

mkdir -p "$ROOT"
if [ ! -f "$ROOT/${TARBALL_DIR}.tar.gz" ]; then
    curl -fsSL "$URL" -o "$ROOT/${TARBALL_DIR}.tar.gz"
fi
if [ ! -d "$ROOT/$DIR" ]; then
    tar -xzf "$ROOT/${TARBALL_DIR}.tar.gz" -C "$ROOT" --transform "s/^${TARBALL_DIR}/${DIR}/"
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
fi

# CI-2: honour $CC (e.g. clang) so the matrix can build with either compiler.
WITH_CC=""
if [ -n "${CC:-}" ]; then
    WITH_CC="--with-cc=$CC"
fi

cd "$ROOT/$DIR"
# shellcheck disable=SC2086
./configure \
    --with-compat \
    --with-debug \
    --with-threads \
    --with-http_realip_module \
    $WITH_CC \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

if [ "$MODE" != "asan" ] && [ "$MODE" != "coverage" ]; then
    make -j"$(nproc)" modules
fi

if [ "$MODE" != "module" ]; then
    make -j"$(nproc)"
    printf 'binary=%s\n' "$ROOT/$DIR/objs/$BINARY"
fi

# Static builds (asan, coverage: --add-module) compile the module INTO the
# binary above; there is no separate objs/*.so to report.
if [ "$MODE" != "asan" ] && [ "$MODE" != "coverage" ]; then
    printf 'module=%s\n' "$ROOT/$DIR/objs/ngx_http_error_abuse_module.so"
fi
