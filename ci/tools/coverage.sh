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
#   3. prove ci/t/ against that instrumented server -> the request-path cases.
#      nginx flushes .gcda on a graceful exit, which is how the worker's arcs
#      reach disk; Test::Nginx stops the server between blocks, so this needs
#      no special handling, but a test that KILLs nginx contributes nothing.
#   4. gcovr over the module's own src/ only.
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

VERSION="${1:-1.31.1}"
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
find "$OBJDIR" -name '*.gcda' -delete

echo "==> Unit tests (instrumented)"
# NGINX_VERSION passed explicitly, with the -coverage suffix run.sh appends via
# NGX_BUILD_SUFFIX, so the instrumented unit run links the SAME objects gcovr
# will scan below -- not a stray debug tree of the same version.
COVERAGE=1 NGINX_VERSION="$VERSION" NGX_BUILD_SUFFIX="-coverage" \
    bash ci/tests/unit/run.sh

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
    --branches
    --print-summary
    --html-details "$OUT/index.html"
    --txt "$OUT/summary.txt"
    # gcov (14.x, this host) resolves the #include headers nginx's core TUs
    # pull in (ngx_event_timer.h, ngx_string.h, ...) relative to gcov's own
    # cwd rather than the compile-time -I path baked into the .gcno, and
    # gcovr 7.x treats "cannot open a header referenced by the source" as a
    # hard error even though none of those headers are in --filter and their
    # coverage is never reported. The nginx CORE objects (not this module's)
    # are the ones that hit this; harmless to ignore since --filter already
    # excludes them from the report gcovr produces.
    --gcov-ignore-errors=no_working_dir_found
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
    --object-directory "$OBJDIR" \
    "$OBJDIR" "$ROOT/ci/tests/unit"

echo
echo "HTML report: $OUT/index.html"
echo "Summary:     $OUT/summary.txt"
