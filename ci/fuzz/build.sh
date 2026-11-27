#!/usr/bin/env bash
#
# Build the error-abuse libFuzzer targets.
# Usage: fuzz/build.sh [output-dir-or-binary]
#
#   - no arg          : build all targets into fuzz/
#   - a directory     : build all targets into that dir
#   - a file path     : build ONLY the snapshot target to that path
#                        (back-compat for the CI step that passes an
#                        explicit fuzz_snapshot output name)
#
# The snapshot/status targets LINK the module's real decision TU
# (../../src/ngx_http_error_abuse_scan.c); the Accept target includes the
# production stats parser header. All targets also link nginx's real
# src/core/ngx_string.c, so the parsers and nginx helpers they walk bytes with
# are production code. That requires a configured nginx tree at
# .build/nginx-<VER>/ -- run ci/tools/ci-build.sh first.
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
WARNINGS="${WARNINGS:--Werror}"

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
    "$CC" $CFLAGS $WARNINGS $ENGINE $NGX_INCS -I"$SRC_DIR" -I"$FUZZ_DIR" \
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
    shopt -s nullglob
    sources=("$FUZZ_DIR"/fuzz_*.c)
    [ "${#sources[@]}" -gt 0 ] || { echo "no fuzz target sources" >&2; exit 1; }
    # Validate the whole output plan before the first compiler can truncate a
    # source, including symlink/hardlink aliases in a separate output directory.
    for source in "${sources[@]}"; do
        target="${source##*/}"
        if [[ ! "${target%.c}" =~ ^fuzz_[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]]; then
            echo "unsupported fuzz target name: $target" >&2
            exit 1
        fi
        output="$DIR/${target%.c}"
        for input in "${sources[@]}"; do
            if [ "$output" -ef "$input" ]; then
                echo "fuzz output $output collides with source $input" >&2
                exit 1
            fi
        done
        case "$output" in
            *.c | *.dict | *.h)
                echo "fuzz output has a reserved source extension: $output" >&2
                exit 1
                ;;
        esac
    done
    for source in "${sources[@]}"; do
        target="${source##*/}"
        build_one "$target" "$DIR/${target%.c}"
    done
fi
