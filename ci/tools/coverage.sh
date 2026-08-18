#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tools/coverage.sh -- line + branch coverage of the MODULE's own sources.
#
#   ci/tools/coverage.sh [version]
#
# Steps:
#   1. ci-build.sh nginx <version> coverage  -> a gcov-instrumented, STATIC
#      (--add-module) nginx binary, in its OWN .build/nginx-<ver>-coverage
#      tree. The .gcno files land under objs/addon/src/.
#   2. ci/tests/unit/run.sh with COVERAGE=1  -> the scan core's boundary cases.
#   3. test_runtime.py against that server -> the module lifecycle, request,
#      Redis, reload, persistence and corruption paths in module.c.
#   4. prove ci/t/ against that instrumented server -> the request-path cases.
#      nginx flushes .gcda on a graceful exit, which is how the worker's arcs
#      reach disk; both drivers stop the server cleanly, so this needs no
#      special handling, but a test that KILLs nginx contributes nothing.
#   5. gcovr over the module's own src/ only.
#
# Env:
#   COVERAGE_FAIL_UNDER   if set, gcovr exits non-zero below this line %.
#                         UNSET by default, and that is a decision, not an
#                         omission: repo policy is meaningful tests over a
#                         percentage. CI publishes the report; it does not fail
#                         on a number, because the cheapest way to move a
#                         number is to write tests that move it without
#                         asserting anything.
#   COVERAGE_OUT          output directory (default .build/coverage).
#   REDIS_SERVER          runtime-suite Redis binary (default
#                         /usr/bin/redis-server).
#
# Exit: 0 on success (or a below-threshold report when COVERAGE_FAIL_UNDER is
# unset), non-zero if a build/test step failed or the threshold was set and
# missed.
#
# WHY THE FILTER IS `src/` AND NOTHING ELSE: nginx's core objects are compiled
# by the same instrumented configure run, so an unfiltered gcovr reports ~1% of
# a 200k-line upstream tree and the module's own numbers vanish into it. The
# module's sources are the coverage target; upstream nginx is not ours to test.
#
# WHY A DISTINCT BUILD TREE: this module's ci-build.sh used to name every
# nginx-<ver> tree the same regardless of mode, so a coverage run would either
# recompile in place over a cached debug tree or, worse, skip recompilation
# entirely -- producing a report that reads a real (but false) 0%. cp5 gave
# `coverage` mode its own <ver>-coverage suffix specifically so this cannot
# happen; see ci-build.sh's comment on TARBALL_DIR vs DIR.
#
# WHY --add-module (static), not --add-dynamic-module: gcov's counters are
# gathered per translation unit at compile time either way, but Test::Nginx
# would otherwise need TEST_NGINX_LOAD_MODULES pointed at a .so that a
# gcov-instrumented dynamic module may not unload/reload cleanly across the
# suite's many server restarts, losing partial .gcda writes. Static removes
# that whole class of flake; ci-build.sh already takes the same static path
# for the asan mode for a related reason.
#
# Extend: a new test layer belongs between steps 2 and 3, before gcovr runs --
# adding it after the report is generated silently contributes nothing.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Keep the standalone default aligned with ci-build.sh's allow-list.
# Path is rooted at REPO_ROOT after cd above.
# shellcheck disable=SC1091
source .github/versions.env
VERSION="${1:-$NGINX_VERSION}"
OUT="${COVERAGE_OUT:-$ROOT/.build/coverage}"

command -v gcovr >/dev/null 2>&1 || {
    echo "ERROR: gcovr not found. Install it: pipx install gcovr" >&2
    exit 2
}

echo "==> Building nginx $VERSION with gcov instrumentation"
bash ci/tools/ci-build.sh nginx "$VERSION" coverage

BUILD="$ROOT/.build/nginx-${VERSION}-coverage"
OBJDIR="$BUILD/objs/addon/src"

# The instrumented objects must actually exist before anything is run against
# them. Without this the suite runs, gcovr finds no .gcno, and the report reads
# "0.0%" -- which looks like a coverage finding rather than a broken build.
if ! compgen -G "$OBJDIR/*.gcno" >/dev/null; then
    echo "FAIL: no .gcno under $OBJDIR -- the build was NOT instrumented." >&2
    echo "      A coverage report from this tree would read 0% and mean nothing." >&2
    echo "      Suspect a cached non-coverage build tree restored into this mode." >&2
    exit 1
fi

# Stale arcs from a previous run would be merged into this one's counts.
# Both trees: $OBJDIR (the nginx-linked module objects, rebuilt by
# ci-build.sh below so its .gcda is already fresh per run) AND
# ci/tests/unit (the unit-harness objects gcovr also scans) -- run.sh
# recompiles the .o/.gcno there every time but does NOT delete a leftover
# .gcda from a previous local run before executing, so a stale arc count
# silently merges into this run's numbers and a deleted test's branch can
# still read 100% covered. Verified: deleting a test case changed nothing
# until this directory was cleared too (step 42 depth pass).
find "$OBJDIR" -name '*.gcda' -delete
find "$ROOT/ci/tests/unit" -name '*.gcda' -delete

echo "==> Unit tests (instrumented)"
# NGINX_VERSION passed explicitly, with the -coverage suffix run.sh appends via
# NGX_BUILD_SUFFIX, so the instrumented unit run links the SAME objects gcovr
# will scan below -- not a stray debug tree of the same version.
COVERAGE=1 NGINX_VERSION="$VERSION" NGX_BUILD_SUFFIX="-coverage" \
    bash ci/tests/unit/run.sh

echo "==> Runtime suite against the instrumented server"
# The coverage build is static, so omit --module: test_runtime.py accepts that
# shape and its generated configurations must exercise the compiled-in module.
# This is deliberately the normal bounded runtime suite, not a reduced smoke
# mode: module.c's lifecycle, Redis, reload and persistence paths otherwise do
# not contribute to this report at all.
python3 ci/tools/test_runtime.py \
    --port "${TEST_BASE_PORT:-18890}" \
    --nginx-binary "$BUILD/objs/nginx" \
    --redis-server "${REDIS_SERVER:-/usr/bin/redis-server}"

echo "==> Test::Nginx suite against the instrumented server"
# Static build (--add-module): the module is compiled INTO objs/nginx, so
# there is no TEST_NGINX_LOAD_MODULES .so to point at here, unlike the
# dynamic-module debug build build-test.yml drives.
# TEST_NGINX_PORT pinned to this job's band for the same reason
# build-test.yml pins one: Test::Nginx::Socket falls back to a hardcoded 1984
# (Test/Nginx/Util.pm), and the build host runs several CI slots at once.
TEST_NGINX_BINARY="$BUILD/objs/nginx" \
TEST_NGINX_TIMEOUT="${TEST_NGINX_TIMEOUT:-20}" \
TEST_NGINX_PORT="${TEST_BASE_PORT:-18890}" \
TEST_NGINX_SERVROOT="$ROOT/ci/t/servroot" \
    prove ci/t/

echo "==> Report"
mkdir -p "$OUT"
GCOVR_ARGS=(
    --root "$ROOT"
    # Only the module's own sources. See the header for why an unfiltered run
    # is worse than useless here.
    --filter "$ROOT/src/"
    --txt-metric branch
    --print-summary
    --html-details "$OUT/index.html"
    --txt "$OUT/summary.txt"
    --json-summary "$OUT/summary.json"
    # Work from the nginx build root, where gcov can resolve nginx's relative
    # headers. The module's source path is absolute, so gcovr still reports it
    # relative to --root. GCC can emit a few negative branch deltas for a
    # multi-worker process; gcovr records that warning and keeps the remaining
    # counters rather than silently dropping module.c from the report.
    --gcov-ignore-errors=no_working_dir_found
    --gcov-ignore-parse-errors=negative_hits.warn
)
if [ -n "${COVERAGE_FAIL_UNDER:-}" ]; then
    GCOVR_ARGS+=(--fail-under-line "$COVERAGE_FAIL_UNDER")
fi

# Both object dirs: the nginx-linked module objects and the unit-test objects,
# which cover the same src/ TUs from a different driver. Merging them is the
# point -- a line reached only by the unit harness is still reached.
# --object-directory, not --gcov-object-directory: the latter was only added in
# gcovr 7.0 as an alias for this one, and an unknown option is a hard argparse
# failure, not a warning. Both spellings work on 7.x; this stays the more
# portable one.
gcovr "${GCOVR_ARGS[@]}" \
    --object-directory "$BUILD" \
    "$OBJDIR" "$ROOT/ci/tests/unit"

# This is a control, not a percentage threshold. Before the runtime driver was
# part of this wrapper, the report listed only scan.c: unit tests and
# Test::Nginx did not drive module.c's runtime paths. Refuse to publish an
# apparently-successful report that omits either production translation unit.
python3 - "$OUT/summary.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
files = {entry["filename"]: entry for entry in report["files"]}
required = (
    "src/ngx_http_error_abuse_module.c",
    "src/ngx_http_error_abuse_scan.c",
)
for name in required:
    entry = files.get(name)
    if entry is None:
        raise SystemExit(f"FAIL: coverage report omitted {name}")
    if entry["line_covered"] == 0:
        raise SystemExit(f"FAIL: coverage report has no executed lines for {name}")
    print(
        f"coverage: {name} lines {entry['line_covered']}/{entry['line_total']}; "
        f"branches {entry['branch_covered']}/{entry['branch_total']}"
    )
PY

echo
echo "HTML report: $OUT/index.html"
echo "Summary:     $OUT/summary.txt"
