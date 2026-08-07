#!/usr/bin/env bash
# ci/linter/selftest.sh -- negative controls for the lint gate itself.
#
# The gate is the thing that decides whether everything else is allowed to
# land, so "the gate ran and said clean" has to be distinguishable from "the
# gate ran nothing and said clean". That distinction is not observable from a
# green lint job: a selector typo used to make run-all.sh print
# "== all linters clean ==" and exit 0 having executed zero checkers.
#
# Every case here asserts the FAILING direction -- a check that only ever
# asserts the passing direction cannot detect its own disarming.
#
# Usage:  ci/linter/selftest.sh
# Exit:   0 all controls held, 1 one or more did not.
#
# Runs in about a second: no case invokes a real checker (LINT_ONLY values are
# either bogus or rejected before dispatch), so no linter needs to be installed.
#
# Extend: add a case() line. Keep each case asserting a specific exit status,
# and prefer a case where the OLD, broken behaviour would have passed.

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 2

rc=0

# case <expected-exit> <description> -- command...
case_() {
    local want="$1" desc="$2"; shift 2
    local out got
    out="$("$@" 2>&1)"; got=$?
    if [ "$got" -eq "$want" ]; then
        echo "ok   $desc (exit $got)"
    else
        echo "FAIL $desc: expected exit $want, got $got" >&2
        echo "$out" | sed 's/^/       | /' >&2
        rc=1
    fi
}

# The regression itself: an unmatched selector must be "could not run" (2),
# not "clean" (0).
case_ 2 "unknown LINT_ONLY exits 2" \
    env LINT_ONLY=nosuchchecker ci/linter/run-all.sh

# ...including when only SOME of the listed names are bogus in a way that
# leaves nothing selected.
case_ 2 "LINT_ONLY of only-bogus names exits 2" \
    env LINT_ONLY="c-lang shellscript" ci/linter/run-all.sh

# The error names the offending value and the known checkers, or nobody can
# act on it.
# Captured first, not piped into grep: `set -o pipefail` would otherwise hand
# the pipeline run-all.sh's exit 2 and the assertion would read as failed no
# matter what the message said.
msg="$(env LINT_ONLY=nosuchchecker ci/linter/run-all.sh 2>&1)"
if printf '%s\n' "$msg" | grep -q 'matched no checker; known: .*sh'; then
    echo "ok   unmatched-selector message names value and known checkers"
else
    echo "FAIL unmatched-selector message is not actionable" >&2
    rc=1
fi

# Positive control: the selector still selects. --list is used rather than a
# real run so this stays independent of which linters are installed.
case_ 0 "--list works" ci/linter/run-all.sh --list

# ----------------------------------------------------------------------------
# workflow_policy.py -- the red path of each policy check.
#
# Every fixture below encodes a bypass that VALID YAML used to walk straight
# through while the checks parsed workflows by regex. Each was verified in both
# directions when it was written: red on the current parser, green on the
# regex one. They are committed rather than planted in .github/workflows/ at
# runtime so no cleanup failure can leave a probe workflow in the live tree.
#
# Extend: add a fixture directory with its own .github/workflows/ and a README
# stating which bypass it encodes, then a policy_ line here.

policy_() {  # policy_ <expected-exit> <fixture> <subcommand>
    local want="$1" fixture="$2" cmd="$3"
    case_ "$want" "policy $cmd: $fixture" \
        env "WORKFLOW_POLICY_ROOT=ci/linter/fixtures/policy/$fixture" \
        python3 ci/linter/workflow_policy.py "$cmd"
}

# THE control that makes the rest mean anything: a fixture tree that is simply
# a valid workflow must be GREEN on all three. Without it, a red on any bypass
# fixture could be the fixture shape rather than the bypass.
policy_ 0 clean runners
policy_ 0 clean ports
policy_ 0 clean docs

# A `.yaml` workflow was invisible to every check: unchecked runner, unchecked
# ports, undocumented gate.
policy_ 1 bypass-yaml-extension runners
policy_ 1 bypass-yaml-extension docs

# `on: [pull_request]` / `on: pull_request` are the same trigger as the mapping
# form; both used to skip the runner-trust check, as did an inline
# pull_request_target.
policy_ 1 bypass-inline-events runners

# `runtime:  # comment` used to yield zero jobs, so a runtime-bearing job with
# no port band reported "no runtime-bearing jobs" and exit 0.
policy_ 1 bypass-commented-job-key ports

# A band verifier placed BELOW the first binder. Declaration, pass-through and
# uniqueness all hold, so the presence checks stay green -- this repo's own
# build-test.yml sat in exactly this shape until 2026-08-02.
policy_ 1 verify-after-bind ports

# A job whose only binder is `prove` (not ci/tools/test_runtime.py) used to be
# exempt from the "declare TEST_BASE_PORT" requirement, even though `prove` is
# already a BINDERS member and the ordering check already treats it as one.
# Live here as a failed negative control: build-test.yml's test-nginx job had no
# band at all and `ports` still reported "3 runtime job(s), all with distinct
# port bands".
policy_ 1 prove-only-binder-exempt ports

# ...and the other half of the same rule: a prove job that DOES declare a band
# but never passes it to Test::Nginx as TEST_NGINX_PORT. Every earlier check
# passes -- declared, distinct, width fits -- and it still binds 1984. Raised by
# CodeRabbit on PR #48 against the commit that made prove a first-class binder:
# widening what must declare a band did not widen what must pass it through.
policy_ 1 prove-band-not-passed-through ports

# A cleanup step that sweeps a literal port range covering a sibling's band.
# Every band declaration in that fixture is correct, so the declaration,
# uniqueness, width and overlap checks are all green -- the kill is the defect.
# CodeRabbit flagged this on PR #19 and the bands added at cp7b did not close
# it: disjoint bands stop two jobs binding the same port, not one job TERMing
# across all of them.
policy_ 1 wide-port-sweep ports

# Two distinct bases 32 apart with no declared width. Uniqueness compares only
# the first port of each band and passes, while max-port.sh assumes 64 and has
# the first job verifying 32 ports into the second. This repo's three live
# bands sat in exactly this shape until 2026-08-04. Pairs with the `clean`
# fixture above, whose bands are 100 apart and therefore legal WITHOUT a
# declared width -- without that pair, the red here is equally consistent with
# "TEST_PORT_WIDTH is now mandatory everywhere".
policy_ 1 overlapping-port-bands ports

# A mistyped pool label in a schedule-only workflow. The trust half of the
# runners check does not apply to a workflow no fork can reach, and skipping it
# used to skip the LABEL membership test with it -- while actionlint, the only
# other thing that reads runner labels, stays silent on the `fromJSON(...)`
# selectors this repo uses everywhere. Six selectors in bump.yml and ci-deep.yml
# had no label checking at all. These two run as a PAIR: the -ok fixture is the
# same file spelled correctly, and without it the red below is equally
# consistent with "every non-PR-reachable workflow is now flagged".
policy_ 1 schedule-only-runner-labels runners
policy_ 0 schedule-only-runner-labels-ok runners

# A workflow_call member carrying its own `push:` runs twice per change and BOTH
# runs are green, so nothing else in the toolchain notices. Measured here on the
# merge of PR #47: six standalone push runs fired on the merge commit after the
# PR's CI had already passed the identical tree. These run as a PAIR: the -ok
# fixture is the same file with `schedule:` (the intended shape, which codeql.yml
# and ci-deep.yml both use), and without it the red above is equally consistent
# with "any member carrying a second trigger is flagged", which is not the rule.
policy_ 1 member-with-push cadence
policy_ 0 member-with-push-ok cadence

# repository_dispatch (and pull_request_target, same class) is per-change like
# push/pull_request, not human/timer-invoked like schedule/workflow_dispatch.
policy_ 1 member-with-repository-dispatch cadence
policy_ 0 member-with-repository-dispatch-ok cadence

# A caller reaching a member with `secrets: inherit` instead of naming what the
# member needs. `inherit` works -- the pipeline stays green and the member gets
# its token -- so the only symptom is a blast radius that silently grows every
# time an unrelated secret is added to the repo. Neither actionlint nor zizmor's
# default posture objects to it on a repo with no secrets configured, which is
# exactly this repo's live state until this PR. These run as a PAIR: the -ok
# fixture is the same topology with the secret named explicitly at the call
# site, and without it the red above is equally consistent with "any workflow
# mentioning a secret is flagged", which is not the rule.
policy_ 1 secrets-inherit secrets
policy_ 0 secrets-typed-ok secrets

# Every glob-discovered checker is named in lint.yml's LINT_ONLY.
#
# run-all.sh picks checkers up by glob, but CI narrows the run to an explicit
# allowlist, and nothing connected the two: a checker added to ci/linter/ ran
# locally and in the pre-commit hook while being silently absent from every PR.
# A gate that runs everywhere except the merge path is missing from the one
# place it is load-bearing -- which is exactly what would have happened to
# ci-cadence here had it been added without this control.
missing=""
only="$(sed -n 's/^ *LINT_ONLY: *//p' .github/workflows/lint.yml)"
for s in ci/linter/lint-*.sh; do
    n="${s#ci/linter/lint-}"; n="${n%.sh}"
    # "c" is deliberately excluded in CI (see lint.yml's header): the src/
    # scanners run in security-scanners.yml instead.
    [ "$n" = "c" ] && continue
    printf '%s\n' "$only" | tr ' ' '\n' | grep -qx "$n" || missing="$missing $n"
done
if [ -z "$missing" ]; then
    echo "ok   every checker is named in lint.yml LINT_ONLY"
else
    echo "FAIL checkers absent from lint.yml LINT_ONLY:$missing" >&2
    echo "       | they run locally and in the hook, but never on a PR" >&2
    rc=1
fi

# WIRING CONTROLS. These assert that a checker is reachable at all, which is a
# weaker claim than "it goes red on a defect" -- the red-direction probes need
# real tools and live in each checker's header instead, so this file keeps its
# no-linter-required property. They exist because both failures below were
# silent: a checker nobody dispatches and a hook nobody runs look exactly like a
# clean tree.
#
# core.hooksPath REPLACES .git/hooks/, so `pre-commit install` writes a file git
# never reads. Measured 2026-08-02: trailing whitespace and a missing final
# newline committed clean past the hooks whose only job is those two things.
# .githooks/pre-commit therefore has to invoke pre-commit itself.
case_ 0 "the commit hook invokes the pre-commit-config hooks" \
    grep -q '^ *pre-commit run' .githooks/pre-commit

# run-all.sh dispatches by glob, so a checker that is not executable, or is
# named outside the lint-*.sh pattern, is silently not run.
case_ 0 "lint-spelling is dispatched by run-all.sh" \
    bash -c 'ci/linter/run-all.sh --list | grep -q lint-spelling.sh'

# Unparsable YAML is "could not run" (2), never "clean" -- GitHub may still
# read a file this parser rejects, so a verdict over the rest of the tree would
# be unsupported. Fixture is generated: a committed broken-YAML file would trip
# yamllint on the real tree.
badroot="$(mktemp -d)"
trap 'rm -rf "$badroot"' EXIT
mkdir -p "$badroot/.github/workflows"
printf 'on: [pull_request\njobs: {\n' > "$badroot/.github/workflows/broken.yml"
case_ 2 "policy runners: unparsable YAML is exit 2, not clean" \
    env "WORKFLOW_POLICY_ROOT=$badroot" python3 ci/linter/workflow_policy.py runners

if [ "$rc" -eq 0 ]; then
    echo "== lint gate selftest: all controls held =="
else
    echo "== lint gate selftest: FAILED ==" >&2
fi
exit "$rc"
