#!/usr/bin/env bash
# Monthly coverage and runner-width policy; all workflows form one contract.
# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"
need python3 "apt-get install python3"
root="$(repo_root)"
if [ "${LINT_MODE:-all}" != staged ]; then
	exec python3 "$root/ci/tools/check_ci_cadence.py"
fi
# A graph needs every workflow from the same index, including unchanged callees.
# Include deletions in the trigger; never refresh or write back the source index.
changed=$(git diff --cached --name-only -- .github/workflows)
if [ -z "$changed" ]; then
	echo 'lint-ci-monthly: no staged workflow files to check'
	exit 0
fi
snapshot=$(mktemp -d "${TMPDIR:-/tmp}/lint-ci-monthly.XXXXXX")
trap 'rm -rf -- "$snapshot"' EXIT
GIT_OPTIONAL_LOCKS=0 git ls-files -z -- .github/workflows |
	GIT_OPTIONAL_LOCKS=0 git checkout-index --prefix="$snapshot/" -z --stdin
python3 -c '
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import check_ci_cadence as policy
policy.ROOT = Path(sys.argv[2])
sys.exit(policy.main())
' "$root/ci/tools" "$snapshot"
