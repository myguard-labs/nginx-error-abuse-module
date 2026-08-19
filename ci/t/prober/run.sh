#!/usr/bin/env bash
#
# Run the error_abuse prober rules against a probe-enabled build.
#
#   ci/t/prober/run.sh [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version; must match what ci/tools/ci-build.sh fetched
#
# NGX_BUILD_MODE selects which per-mode build tree to use (default: debug), so
# a mode switch never reuses another mode's object files; this is passed
# through to the harness as PROBER_BUILD.
#
# The engine lives in ci/t/harness (nginx-test-harness) and knows nothing about
# this module: this only supplies the four things that are ours -- which .so to
# look in, which directive proves the harness build, and where the conf and
# rules are. Everything else (boot, teardown, TAP, the delta engine, the pid
# oracle, the error-log scrape) is the harness's.
#
# The build must have been made with TEST_HARNESS=1, otherwise
# error_abuse_probe does not exist and the config fails to load; the harness
# checks for that up front by inspecting the binary rather than letting it
# surface as a confusing connect error.
set -euo pipefail

cd "$(dirname "$0")"

HERE="$PWD"

if [ ! -x ../harness/prober/run.sh ]; then
    echo "Bail out! ci/t/harness is empty -- run: git submodule update --init"
    exit 1
fi

# The harness resolves conf/rules relative to its own directory, so both are
# passed as absolute paths out of this one.
export PROBER_MODULE="ngx_http_error_abuse_module.so"
export PROBER_DIRECTIVE="error_abuse_probe"
export PROBER_CONF="$HERE/conf/prober.conf"
export PROBER_RULES="$HERE/rules/*.rule"
# SC2155: split declare from assign so a failed cd/pwd surfaces its exit status
# instead of being masked by export's own success.
PROBER_ROOT="$(cd ../../.. && pwd)"
export PROBER_ROOT

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.1}"
NGX_BUILD_MODE="${NGX_BUILD_MODE:-debug}"
PROBER_BUILD="${PROBER_BUILD:-$PROBER_ROOT/.build/${FLAVOR}-${VERSION}-${NGX_BUILD_MODE}}"
export PROBER_BUILD

# NOT setting PROBER_ALLOW_LOG on purpose. 01-fault.rule drives the slab
# allocator to failure, which is usually the kind of thing that has to be
# exempted from the harness's [alert]/[crit]/[emerg] gate -- but this module
# logs its zone-full path at [error] (NGX_LOG_ERR, see the F-3 branch in the
# header filter), which is BELOW that gate, and nginx core logs nothing at all
# when a module's own slab_alloc returns NULL. So there is nothing to exempt.
# An allowlist here would be a blanket exemption for a condition that does not
# occur, and would silently cover a real [crit] the day one appears.

exec ../harness/prober/run.sh "$@"
