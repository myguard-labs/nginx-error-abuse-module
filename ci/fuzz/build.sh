#!/usr/bin/env bash
#
# Build the error-abuse libFuzzer targets.
# Usage: fuzz/build.sh [output-dir-or-binary]
#
#   - no arg          : build both targets into fuzz/
#   - a directory     : build both targets into that dir
#   - a file path     : build ONLY the snapshot target to that path
#                        (back-compat for the CI step that passes an
#                        explicit fuzz_snapshot output name)
#
# Both targets LINK the module's real decision TU
# (../../src/ngx_http_error_abuse_scan.c) plus nginx's real
# src/core/ngx_string.c, so the parsers under test and the
# ngx_atoi()/ngx_strlchr() they walk bytes with are production code. That
# requires a configured nginx tree at .build/nginx-<VER>/ -- run
# ci/tools/ci-build.sh first.
#
# This replaced extract_parser.sh, which sed-sliced the two function bodies out
# of the module .c and compiled them against ngx_shim.h's re-typed copies of the
# nginx helpers and the on-disk constants. That arrangement fuzzed a textual
# copy of the parser against a copy of the decoder: neither drift was visible to
# the build, and lessons.md records a format change that broke the harness's
# hand-maintained stride. Linking the real TU removes all three copies.
#
# Requires clang with libFuzzer (clang >= 6). CFLAGS/CC overridable for
# OSS-Fuzz / ClusterFuzzLite, which pass their own sanitizer flags.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$FUZZ_DIR/../.." && pwd)"
SRC_DIR="$REPO_ROOT/src"
CC="${CC:-clang}"

# OSS-Fuzz sets $LIB_FUZZING_ENGINE and its own $CFLAGS; honour them.
ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
CFLAGS="${CFLAGS:--g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined}"

# --- Locate the configured nginx source tree. ------------------------------
# The targets need nginx HEADERS (objs/ngx_auto_config.h) plus the real
# src/core/ngx_string.c. Fail loudly rather than fall back to a copy: a fuzz run
# against a stubbed decoder is exactly the silent no-op this seam removed.
NGX_SRC="${NGX_SRC:-}"
if [ -z "$NGX_SRC" ]; then
    for d in "$REPO_ROOT"/.build/nginx-*/; do
        if [ -f "$d/objs/ngx_auto_config.h" ]; then
            NGX_SRC="${d%/}"
        fi
    done
fi

if [ -z "$NGX_SRC" ] || [ ! -f "$NGX_SRC/objs/ngx_auto_config.h" ]; then
    cat >&2 <<'EOF'
✗ no configured nginx tree found under .build/

  The fuzz targets link nginx's real src/core/ngx_string.c and need
  objs/ngx_auto_config.h, which only exists after nginx is configured.

  Run first:  bash ci/tools/ci-build.sh
  Or point at a tree explicitly:  NGX_SRC=/path/to/nginx-1.31.3 ci/fuzz/build.sh
EOF
    exit 1
fi

echo "Using nginx source: $NGX_SRC"

NGX_INCS="-I$NGX_SRC/src/core -I$NGX_SRC/src/event -I$NGX_SRC/src/event/modules \
    -I$NGX_SRC/src/os/unix -I$NGX_SRC/objs \
    -I$NGX_SRC/src/http -I$NGX_SRC/src/http/modules"

build_one() {
    local src="$1" out="$2"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS $ENGINE $NGX_INCS -I"$SRC_DIR" -I"$FUZZ_DIR" \
        "$FUZZ_DIR/$src" \
        "$FUZZ_DIR/ngx_stubs.c" \
        "$SRC_DIR/ngx_http_error_abuse_scan.c" \
        "$NGX_SRC/src/core/ngx_string.c" \
        -o "$out"
    echo "✓ built fuzz target: $out"
}

ARG="${1:-}"
if [ -n "$ARG" ] && [ ! -d "$ARG" ]; then
    # Explicit single-file output path -> snapshot target only (CI compat).
    build_one fuzz_snapshot.c "$ARG"
else
    DIR="${ARG:-$FUZZ_DIR}"
    build_one fuzz_snapshot.c "$DIR/fuzz_snapshot"
    build_one fuzz_statuses.c "$DIR/fuzz_statuses"
fi
