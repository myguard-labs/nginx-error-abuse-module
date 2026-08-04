#!/usr/bin/env bash
# sync-stamp.sh -- content-hash stamp for the CI files copied from the skeleton.
#
# THE PROBLEM. This module's .github/ tree was adopted from
# labs/nginx-skeleton-module and then edited locally. Neither side has a cheap
# way to answer "is our copy of build-test.yml still the one the skeleton ships,
# or did we edit it / did the skeleton move?" -- short of diffing every file by
# hand. The stamps make that a sha comparison: `--list` on both repos, diff the
# two outputs, and every drifted file names itself.
#
# WHY A HASH, NOT A TIMESTAMP. A `# updated: 2026-08-04` header answers "when
# did someone touch this", which is not the question. It moves on no-op
# reformats, it does NOT move when a file is edited without discipline, and two
# repos with identical content can carry different dates -- so a human still has
# to diff to find out. A content hash answers the actual question, mechanically:
# equal sha means equal content, no judgement involved. It is the same reasoning
# .github/versions.env already applies to tarballs, and install-linters.sh to
# the actionlint binary: pin the CONTENT, not a label describing it.
#
# THE SELF-REFERENCE. A hash of a file cannot live in that file -- writing it
# changes the content it describes. So the stamp line itself is EXCLUDED from
# the digest: the hash covers the file with its `# sync-sha:` line removed. That
# makes it stable across re-stamping and lets `--check` recompute it in place.
#
# Usage:
#   ci/tools/sync-stamp.sh            # rewrite every stamp (use after editing)
#   ci/tools/sync-stamp.sh --check    # verify; exit 1 on any stale/missing stamp
#   ci/tools/sync-stamp.sh --list     # print path<TAB>sha, for a consuming repo
#
# --check is what CI runs: it fails when a tracked file was edited without
# re-stamping, so the stamps cannot rot into decoration.
#
# SCOPE: the files actually shared with the skeleton -- workflows, the scripts
# they call, and composite actions. ci/linter/ and ci/tools/ are NOT stamped;
# they are a much wider surface carrying this module's own name, paths and
# thresholds throughout, so they drift from the skeleton by design and a stamp
# on them would report drift that is the intended state.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

MODE=stamp
case "${1:-}" in
    --check) MODE=check ;;
    --list)  MODE=list ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    "") ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

# NUL-delimited: paths with spaces must not split. -print0/-d '' throughout.
targets() {
    find .github/workflows -maxdepth 1 -name '*.yml' -print0
    find .github/scripts    -maxdepth 1 -name '*.sh'  -print0
    find .github/actions    -name 'action.yml'        -print0
}

# The digest of a file with its own stamp line stripped -- see THE
# SELF-REFERENCE above.
content_sha() {
    grep -v '^# sync-sha: ' -- "$1" | sha256sum | cut -d' ' -f1
}

stamp_of() {
    sed -n 's/^# sync-sha: \([0-9a-f]\{64\}\)$/\1/p' -- "$1" | head -1
}

# Insert the stamp as a LONE line, adding no blank line of its own.
#
# The blank line matters more than it looks. content_sha() strips only the
# `# sync-sha: ` line, so anything else this function adds becomes part of the
# content and changes the very digest just recorded -- every file then reads
# STALE the instant after it was stamped. (Observed: the first version printed
# a trailing "" and all 14 files failed --check immediately.) So: insert one
# line, remove one line, and the operation is exactly invertible.
#
# Placement: after a shebang if there is one (it must stay line 1), otherwise
# at the very top. Not "after the leading comment block" -- .github/workflows
# files start with `name:` and their comments come after it, so there is no
# single header shape to aim for, and the top is unambiguous for a reader
# looking to compare two repos' copies.
insert_stamp() {
    local f="$1" sha="$2" tmp
    tmp="$(mktemp)"
    awk -v sha="$sha" '
        NR == 1 && /^#!/ { print; print "# sync-sha: " sha; done = 1; next }
        NR == 1 && !done { print "# sync-sha: " sha; done = 1 }
        { print }
        END { if (!done) print "# sync-sha: " sha }
    ' "$f" > "$tmp"
    # Preserve the mode: .github/scripts/*.sh are executable and a plain mv
    # from mktemp would drop that to 0600.
    chmod --reference="$f" "$tmp"
    mv "$tmp" "$f"
}

rc=0
count=0
while IFS= read -r -d '' f; do
    count=$((count + 1))
    want="$(content_sha "$f")"
    have="$(stamp_of "$f")"
    case "$MODE" in
        list)
            printf '%s\t%s\n' "$f" "$want"
            ;;
        check)
            if [ -z "$have" ]; then
                echo "MISSING stamp: $f" >&2; rc=1
            elif [ "$have" != "$want" ]; then
                echo "STALE stamp:   $f" >&2
                echo "  recorded: $have" >&2
                echo "  actual:   $want" >&2
                rc=1
            fi
            ;;
        stamp)
            if [ "$have" = "$want" ]; then
                continue
            fi
            # Drop any existing stamp before inserting the new one, or
            # re-stamping accumulates lines.
            if [ -n "$have" ]; then
                tmp="$(mktemp)"
                grep -v '^# sync-sha: ' -- "$f" > "$tmp"
                chmod --reference="$f" "$tmp"
                mv "$tmp" "$f"
            fi
            insert_stamp "$f" "$want"
            echo "stamped: $f"
            ;;
    esac
done < <(targets)

if [ "$count" -eq 0 ]; then
    # A selector that matches nothing must not report success -- that is how a
    # gate silently stops gating (same reasoning as ci/linter/selftest.sh).
    echo "sync-stamp: matched no files -- wrong working directory?" >&2
    exit 2
fi

if [ "$MODE" = check ]; then
    [ "$rc" -eq 0 ] && echo "sync-stamp: all $count file(s) current"
    [ "$rc" -ne 0 ] && echo "sync-stamp: re-run ci/tools/sync-stamp.sh to fix" >&2
fi
exit "$rc"
