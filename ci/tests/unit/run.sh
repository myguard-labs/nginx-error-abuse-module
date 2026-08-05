#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tests/unit/run.sh -- build and run the scan-core unit tests.
#
#   ci/tests/unit/run.sh                  # build with warnings-as-errors, run
#   ci/tests/unit/run.sh clean            # remove the built binary
#   COVERAGE=1 ci/tests/unit/run.sh       # also instrument, so
#                                         # ci/tools/coverage.sh can gcov src/
#
# Env:
#   CC                 compiler (default cc). Takes a full driver line, so
#                      CC="gcc -m32" runs the suite as a 32-bit binary.
#   NGINX_VERSION       version directory under .build/ to take headers and
#                        ngx_string.c from (default 1.31.1, matching
#                        ci/tools/ci-build.sh's own default).
#   NGX_BUILD_SUFFIX     appended to the nginx-<ver> dir name, e.g. "-coverage"
#                         so this can be pointed at ci-build.sh's distinct
#                         coverage tree without touching the debug one.
#                         Default "-debug": cp7a gave every ci-build.sh mode
#                         its OWN tree (.build/nginx-<ver>-<mode>, never a
#                         bare .build/nginx-<ver>) so a cached debug tree can
#                         never be silently restored into an asan/coverage
#                         job. Plain `ci/tools/ci-build.sh nginx <ver>`
#                         (mode defaults to debug) is what this script's own
#                         usage line above tells you to run first, so the
#                         default here has to match that tree, not the old
#                         suffix-less one.
#
# Exit: 0 all checks passed, 1 a check failed or the build failed.
#
# Runs in well under a second and needs no nginx process, no network and no
# root -- so it is the layer this module can afford to run on every save.
#
# WHAT IT DOES *NOT* DO, deliberately: it does not shim nginx. The test binary
# links the REAL src/core/ngx_string.c out of the build tree, which is why a
# tree must exist first (ci/tools/ci-build.sh). A shimmed decoder would make
# this hermetic and worthless: ngx_atoi()/ngx_strlchr() are the exact surface
# ngx_http_error_abuse_parse_statuses() walks untrusted bytes with, so a test
# asserting against a private copy of them asserts only that the copy is
# self-consistent. Paying a build dependency to keep the decoder honest is the
# right side of that trade.
#
# -Werror applies to OUR translation units only. ngx_string.c is upstream code
# we neither own nor patch, and gating on warnings in it would make an nginx
# version bump look like a test regression.
#
# SEEN RED -- every mutation below was APPLIED to src/ngx_http_error_abuse_scan.c
# and the named check was observed failing (2026-08-04). Re-run them after
# touching the scan core or this script: a check that has never failed is not
# known to be a check.
#
#   * status-range ceiling removed -- change
#     `final > NGX_HTTP_ERROR_ABUSE_MAX_STATUS` to `final > 700`
#       -> "status 600 alone is rejected (ceiling)" FAILS.
#   * empty-element check dropped -- delete `if (end == p) { return
#     NGX_HTTP_ERROR_ABUSE_STATUSES_EMPTY_ELEMENT; }`
#       -> "leading empty element (\",404\") is EMPTY_ELEMENT" FAILS (falls
#          through to a RANGE rc from ngx_atoi(-1) instead).
#   * trailing-comma check dropped -- delete `if (p == last) { return
#     NGX_HTTP_ERROR_ABUSE_STATUSES_TRAILING_COMMA; }`
#       -> "single trailing comma (\"404,\") is TRAILING_COMMA" FAILS.
#   * final stride check widened -- change `return (p == last) ? NGX_OK :
#     NGX_ERROR;` to `return (p <= last) ? NGX_OK : NGX_ERROR;`
#       -> "stride short of last by one byte is rejected (off-by-one)" FAILS.
#   * LE encode byte order flipped -- in ngx_http_error_abuse_put_u32(), swap
#     `p[0] = (u_char) v;` and `p[3] = (u_char) (v >> 24);`
#       -> "put_u32 writes little-endian bytes" FAILS (round-trip test alone
#          would NOT have caught this -- see the header note in test_scan.c).
#
# THREE MUTATIONS THAT SURVIVE, recorded so the next person does not mistake
# any of them for a gap in this file:
#   * status-range floor removed -- change `first < 100 || final < first` to
#     `final < first` (drop the `first < 100` half of the guard). Has two
#     effects depending on input: parse_str("0") fails the check cleanly, so
#     "status 0 alone is rejected (floor)" (SEEN RED in 2026-08-04 run, test
#     at ci/tests/unit/test_scan.c:139) runs first and the suite goes red on a
#     clean check() FAIL; parse_str("abc") yields first=final=-1 from ngx_atoi(),
#     enters the fill loop as `status = (ngx_uint_t) -1` (enormous unsigned
#     value), and crashes with SIGBUS/SIGSEGV before any check() runs. The
#     mutation IS caught, just not as a clean check() FAIL line for the "abc"
#     case. Recorded rather than "fixed" as a single entry because the suite
#     exit goes non-zero in both paths (bash reports the killed child's signal as
#     exit status), and separating them would mean pre-validating the exact bug
#     under test, which defeats the point. This entry carries both facts because
#     the next maintainer must trust the ledger and know the suite saw the
#     `"0"` FAIL-on-check path first.
#   * record-length bound weakened by 1 -- change
#     `(last - p) < NGX_HTTP_ERROR_ABUSE_FILE_REC_LEN` to
#     `... - 1` in ngx_http_error_abuse_validate_snapshot(). ALL 41 checks stay
#     green -- including case_snapshot_accept_two_records() and every other
#     multi-record case added 2026-08 specifically to try to close this gap.
#     Root cause, confirmed to generalize to ANY record count: `p` only ever
#     increases across the loop (each record adds FILE_REC_LEN plus a
#     non-negative payload). Once a weakened header bound lets `p` overshoot
#     `last` on some record -- here by exactly 1 byte, from decoding a header
#     that is 1 byte short -- no later record's strictly-positive advance can
#     bring `p` back down to equal `last`, so the function's own final
#     `p == last` stride check independently rejects every such overshoot,
#     with 1 record or with N. Verified by exhaustive simulation (event counts
#     0-10, byte offsets swept across up to 3 records) and by building this
#     exact mutation and running the full multi-record suite: still 41/41
#     green. See the investigation note on case_snapshot_accept_two_records()
#     in test_scan.c for the full argument and the exact commands run. The
#     mutation IS a real bug (a 1-byte out-of-bounds READ) -- it is simply not
#     one this return-code-asserting unit-test file can observe; that is
#     exactly the job ci/fuzz/ (ASan-built) exists to do.
#   * payload bound dropped -- delete the `if ((size_t) (last - p) < payload)`
#     check in ngx_http_error_abuse_validate_snapshot(). ALL 41 checks stay
#     green, for the identical monotonic-`p` reason as the record-length bound
#     above -- confirmed the same way, by exhaustive simulation and by
#     building this exact mutation against the full multi-record suite. Kept
#     as defense in depth (and load-bearing on a 32-bit build, where pointer
#     arithmetic has far less headroom before `p += payload` wraps) but not
#     provably load-bearing, at the return-code level, from any unit test in
#     this file, at any record count. See
#     case_snapshot_reject_payload_overrun() in test_scan.c.
#
# Extend: add a CASE() to test_scan.c and one line to its main(). New source
# file in src/ -> add it to the build commands below.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
BIN="$DIR/test_scan"

if [ "${1:-}" = "clean" ]; then
    rm -f "$BIN" "$DIR"/*.o "$DIR"/*.gcda "$DIR"/*.gcno
    echo "unit test binary removed"
    exit 0
fi

VERSION="${NGINX_VERSION:-1.31.1}"
NGX_SRC="$ROOT/.build/nginx-${VERSION}${NGX_BUILD_SUFFIX:--debug}"

if [ ! -f "$NGX_SRC/objs/ngx_auto_config.h" ]; then
    cat >&2 <<EOF
ERROR: no configured nginx tree at $NGX_SRC

The unit tests link nginx's real src/core/ngx_string.c and need
objs/ngx_auto_config.h, which only exists after nginx is configured.

Run first:  bash ci/tools/ci-build.sh nginx ${VERSION}
EOF
    exit 1
fi
echo "Using nginx source: $NGX_SRC"

CC="${CC:-cc}"

NGX_INCS=(
    -I"$NGX_SRC/src/core"
    -I"$NGX_SRC/src/event"
    -I"$NGX_SRC/src/event/modules"
    -I"$NGX_SRC/src/os/unix"
    -I"$NGX_SRC/objs"
    -I"$NGX_SRC/src/http"
    -I"$NGX_SRC/src/http/modules"
)

# Our code: the full warning wall.
OWN_CFLAGS=(-g -O1 -Wall -Wextra -Wshadow -Wstrict-prototypes -Werror)
# Upstream code: warnings visible, not fatal.
NGX_CFLAGS=(-g -O1 -Wall)

if [ "${COVERAGE:-0}" = 1 ]; then
    OWN_CFLAGS+=(--coverage)
    NGX_CFLAGS+=(--coverage)
    LINK_EXTRA=(--coverage)
else
    LINK_EXTRA=()
fi

# ci/fuzz/ngx_stubs.c is reused, not copied: it already resolves the
# allocator/log symbols ngx_string.c drags in, and aborts if the scan path ever
# reaches one. A second copy here would be a second thing to keep in sync with
# the scan core's no-allocate contract.
echo "==> Building $BIN with ${CC}"
# shellcheck disable=SC2086  # $CC may legitimately carry flags (e.g. "gcc -m32")
$CC "${OWN_CFLAGS[@]}" "${NGX_INCS[@]}" -I"$ROOT/src" -c "$DIR/test_scan.c" \
    -o "$DIR/test_scan.o"
# shellcheck disable=SC2086
$CC "${OWN_CFLAGS[@]}" "${NGX_INCS[@]}" -I"$ROOT/src" \
    -c "$ROOT/src/ngx_http_error_abuse_scan.c" \
    -o "$DIR/ngx_http_error_abuse_scan.o"
# shellcheck disable=SC2086
$CC "${OWN_CFLAGS[@]}" "${NGX_INCS[@]}" -c "$ROOT/ci/fuzz/ngx_stubs.c" \
    -o "$DIR/ngx_stubs.o"
# shellcheck disable=SC2086
$CC "${NGX_CFLAGS[@]}" "${NGX_INCS[@]}" -c "$NGX_SRC/src/core/ngx_string.c" \
    -o "$DIR/ngx_string.o"
# shellcheck disable=SC2086
$CC "${LINK_EXTRA[@]}" -o "$BIN" \
    "$DIR/test_scan.o" "$DIR/ngx_http_error_abuse_scan.o" "$DIR/ngx_stubs.o" \
    "$DIR/ngx_string.o"

echo "==> Running"
"$BIN"
