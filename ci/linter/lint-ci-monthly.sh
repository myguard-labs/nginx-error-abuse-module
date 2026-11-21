#!/usr/bin/env bash
# Monthly coverage and runner-width policy; all workflows form one contract.
# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"
need python3 "apt-get install python3"
root="$(repo_root)"
selected=false
if [ "$#" -gt 0 ]; then
	for path in "$@"; do
		path=${path#"$root"/}
		while [[ "$path" == ./* ]]; do path=${path#./}; done
		case "$path" in
		.github/workflows/*.yml | .github/workflows/*.yaml) selected=true ;;
		esac
	done
	if [ "$selected" = false ]; then
		echo 'lint-ci-monthly: no selected workflow files to check'
		exit 0
	fi
fi
if [ "${LINT_MODE:-all}" != staged ]; then
	exec python3 "$root/ci/tools/check_ci_cadence.py"
fi
# A graph needs every workflow from the same index, including unchanged callees.
# Include deletions in the trigger; never refresh or write back the source index.
changed=$(git diff --cached --name-only -- ':(top).github/workflows')
if [ -z "$changed" ] && [ "$selected" = false ]; then
	echo 'lint-ci-monthly: no staged workflow files to check'
	exit 0
fi
snapshot=$(mktemp -d "${TMPDIR:-/tmp}/lint-ci-monthly.XXXXXX")
trap 'rm -rf -- "$snapshot"' EXIT
GIT_OPTIONAL_LOCKS=0 python3 - "$snapshot" <<'PY'
import os
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
entries = subprocess.check_output(
    ["git", "ls-files", "--stage", "--full-name", "-z", "--", ":(top).github/workflows"]
)
for entry in entries.split(b"\0"):
    if not entry:
        continue
    metadata, name = entry.split(b"\t", 1)
    mode, blob, stage = metadata.split()
    if stage != b"0" or mode not in (b"100644", b"100755"):
        sys.exit("lint-ci-monthly: workflow index entry is unmerged or not a regular file")
    target = root / os.fsdecode(name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(subprocess.check_output(["git", "cat-file", "blob", blob]))
PY
python3 -c '
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import check_ci_cadence as policy
policy.ROOT = Path(sys.argv[2])
sys.exit(policy.main())
' "$root/ci/tools" "$snapshot"
