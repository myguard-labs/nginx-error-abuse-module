#!/usr/bin/env bash
# Monthly coverage and runner-width policy; all workflows form one contract.
# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"
need python3 "apt-get install python3"
exec python3 "$(git rev-parse --show-toplevel)/ci/tools/check_ci_cadence.py"
