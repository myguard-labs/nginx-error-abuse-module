#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Repo-policy checks over .github/workflows/ that no off-the-shelf linter makes.

    ci/linter/workflow_policy.py runners     runner trust boundary + pool labels
    ci/linter/workflow_policy.py ports       per-job test port bands
    ci/linter/workflow_policy.py docs        README <-> workflows drift

Each subcommand is wrapped by a ci/linter/lint-*.sh so run-all.sh picks it up by
glob and a human can select it with LINT_ONLY. Exit: 0 clean, 1 findings,
2 could not run.

WHY THESE ARE NOT actionlint OR zizmor RULES. Both of those read a workflow
against GENERAL knowledge -- syntax, and a catalogue of known attack shapes.
The three checks here encode facts about THIS repo that no general tool can
know: which self-hosted labels exist, that the runners are persistent and
shared with package builds, which port band each job owns, and which files
document the pipeline. They are the checks that go red when a NEW workflow is
added without the property every existing one happens to have -- the case where
copying an existing file is the only thing standing between the repo and a
regression, and nothing enforces the copy.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised by the selftest doc
    print(
        "workflow_policy: PyYAML not installed (apt-get install python3-yaml).\n"
        "  Refusing to run rather than degrading to a regex scan: every check\n"
        "  here was bypassable by VALID YAML while it parsed workflows by\n"
        "  regex, which is the vacuous-gate shape this file exists to prevent.",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

# WORKFLOW_POLICY_ROOT points the checks at a fixture tree instead of the repo.
# It exists so ci/linter/selftest.sh can assert the FAILING direction of every
# check against a committed, readable fixture -- rather than by planting a file
# in the live .github/workflows/ and hoping the cleanup runs. A check whose red
# path is never exercised is indistinguishable from one that cannot go red.
ROOT = pathlib.Path(
    os.environ.get("WORKFLOW_POLICY_ROOT")
    or pathlib.Path(__file__).resolve().parents[2]
)
WORKFLOWS = ROOT / ".github" / "workflows"


class PolicyError(Exception):
    """Could not run the check (exit 2) -- never confused with "clean"."""


def _trust_split(labels: list[str]) -> str:
    """The one approved runner selector shape, for a given self-hosted label set.

    Built rather than pasted three times: the FORK ARM is the security-relevant
    half and must be byte-identical in every accepted form. Three hand-written
    copies drift, and a drifted copy is silently accepted by the membership test
    below while meaning something slightly different.
    """
    inner = ",".join(f'"{label}"' for label in labels)
    return (
        "${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || "
        + f"fromJSON('[{inner}]') }}}}"
    )


# Accepted self-hosted label sets. Each keeps FORK pull requests on a
# GitHub-hosted runner and everything else on the self-hosted pool.
#
# Why the split matters here specifically: a `pull_request`-triggered job checks
# out and EXECUTES scripts from the PR head. The self-hosted runners are persistent
# and shared with the Debian package builds, so running a fork's code on them is
# arbitrary code execution on the build host, with whatever the previous job
# left behind still on disk. The hosted arm is what makes this repo safe to
# accept outside contributions to -- which a public template repo exists to do.
#
# Widening the label set only changes WHICH slots are eligible, so a new entry
# here is fine. Changing the fork arm is not, which is why it is not a parameter.
TRUST_SPLITS = frozenset(
    _trust_split(labels)
    for labels in (
        ["self-hosted", "builder02", "lxc"],
        ["self-hosted", "builder02"],
        ["self-hosted", "builder02", "docker"],
    )
)

HOSTED = re.compile(r"ubuntu-(?:latest|[0-9]+\.[0-9]+)")

# The runtime driver. A job that starts it is a "runtime-bearing" job and owes
# the port-band declaration checked below.
RUNTIME_DRIVER = "ci/tools/test_runtime.py"

# The band verifier, and everything that BINDS the band. The ordering check
# below needs both: a verify step is only a guard for the binders that come
# after it, and `prove` is a binder even though it is not the runtime driver.
BAND_VERIFIER = "ci/tools/max-port.sh"
# Word-bounded on purpose: a bare "prove" substring also matches `approve`,
# `improve` and `prover`, and a run block that merely says "improve the fixture"
# is not a binder. A shell comment inside a run block still counts -- treating a
# commented-out binder as absent is the safe direction here, since the finding is
# about the step that DOES bind.
BINDERS = (
    re.escape(RUNTIME_DRIVER),
    r"(?<![\w./-])prove(?![\w./-])",
    re.escape("ci/tools/coverage.sh"),
)
BINDER_RE = re.compile("|".join(BINDERS))


def workflows() -> list[pathlib.Path]:
    """Every workflow file, BOTH extensions.

    GitHub reads `*.yml` and `*.yaml` alike. Globbing one of them made all three
    checks below skip a `.yaml` workflow entirely -- an undocumented, unchecked,
    possibly self-hosted PR entry point that reported clean.
    """
    return sorted(
        [*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")],
        key=lambda p: p.name,
    )


def load(path: pathlib.Path) -> dict:
    """Parse a workflow. A file that will not parse is exit 2, never clean."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path.name}: unparsable YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise PolicyError(f"{path.name}: top level is not a mapping")
    return doc


def events(doc: dict) -> set[str]:
    """The trigger names, from any of the three legal `on:` spellings.

    `on: [pull_request]`, `on: pull_request` and the indented mapping form mean
    exactly the same thing to GitHub. Only the mapping form was recognised
    before, so the two others walked past the runner-trust check.

    PyYAML resolves the bare key `on` to the boolean True (YAML 1.1 truthiness),
    so the True key is where the node actually lands unless it was quoted.
    """
    node = doc.get("on", doc.get(True))
    if isinstance(node, str):
        return {node}
    if isinstance(node, list):
        return {str(e) for e in node}
    if isinstance(node, dict):
        return {str(k) for k in node}
    return set()


def jobs(doc: dict) -> list[tuple[str, dict]]:
    """(name, node) for every job. A non-mapping `jobs:` yields nothing."""
    node = doc.get("jobs")
    if not isinstance(node, dict):
        return []
    return [(str(k), v) for k, v in node.items() if isinstance(v, dict)]


def selector(node) -> str:
    """Render a `runs-on:` node back to one comparable string.

    The list and mapping forms are rendered rather than flattened so that a
    `runs-on: [self-hosted, builder02]` fails the membership test as ONE finding
    naming the whole selector, instead of one confusing finding per label.
    """
    if isinstance(node, str):
        return node.strip()
    if isinstance(node, list):
        return "[" + ", ".join(selector(v) for v in node) + "]"
    if isinstance(node, dict):
        return "{" + ", ".join(f"{k}: {selector(v)}" for k, v in node.items()) + "}"
    return str(node)


def report(name: str, errors: list[str], ok_msg: str) -> int:
    if errors:
        print(f"{name}: {len(errors)} finding(s)", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(f"{name}: {ok_msg}")
    return 0


# --------------------------------------------------------------------------
# runners


def check_runners() -> int:
    errors: list[str] = []
    for path in workflows():
        doc = load(path)
        trigger = events(doc)

        # pull_request_target runs with the BASE repo's secrets against the
        # HEAD's code. There is no configuration of it that is safe here, so it
        # is refused outright rather than conditioned.
        if "pull_request_target" in trigger:
            errors.append(f"{path.name}: pull_request_target is forbidden")

        # PR-REACHABLE, not just pull_request-triggered. Every heavy workflow in
        # this repo is `workflow_call`-only and reached from ci.yml, whose sole
        # trigger IS pull_request -- and a called workflow inherits the caller's
        # event payload, so `github.event.pull_request.head.repo.fork` is
        # populated inside it. A check that only looked for a literal
        # `pull_request:` trigger would therefore pass every single one of them
        # while checking nothing, which is precisely the vacuous-gate shape this
        # repo keeps re-learning.
        pr_reachable = bool(trigger & {"pull_request", "workflow_call"})

        wf_jobs = jobs(doc)
        if not wf_jobs:
            if pr_reachable:
                errors.append(f"{path.name}: PR-reachable workflow declares no jobs")
            continue
        for job, node in wf_jobs:
            # A `uses:` job is a call into another workflow, which carries its
            # own runs-on and is checked as its own file. It owes no runner.
            if "uses" in node:
                continue
            if "runs-on" not in node:
                # Only a PR-reachable job OWES a runner declaration here: that is
                # the trust question. A schedule-only job without one is invalid
                # to GitHub itself and is not this check's business.
                if pr_reachable:
                    errors.append(
                        f"{path.name}:{job} is PR-reachable and declares no runs-on"
                    )
                continue
            runner = selector(node["runs-on"])
            if runner in TRUST_SPLITS or HOSTED.fullmatch(runner):
                continue
            if pr_reachable:
                errors.append(
                    f"{path.name}:{job} has runs-on: {runner} -- must be "
                    "GitHub-hosted or an approved fork-aware trust split "
                    "(see TRUST_SPLITS in ci/linter/workflow_policy.py)"
                )
                continue
            # NOT PR-reachable, so there is no fork-trust question to answer --
            # but the membership test still runs, because nothing else in the
            # toolchain checks these labels at all.
            #
            # actionlint validates runner labels only for a LITERAL `runs-on`.
            # Every self-hosted selector in this repo is a `fromJSON(...)`
            # ternary, so actionlint goes QUIET on all of them regardless of
            # what .github/actionlint.yaml declares -- and silence reads exactly
            # like a pass. The exact-string membership test above is what
            # actually catches a mistyped pool label, so skipping it for
            # schedule-only workflows left bump.yml and ci-deep.yml (six
            # selectors) with no label checking anywhere. Measured 2026-08-02:
            # `builder02` -> `buidler02` in build-test.yml was reported, the
            # same edit in bump.yml and ci-deep.yml was silent on both this
            # check and actionlint.
            #
            # A typo here does not fail at lint time or at dispatch time. It
            # fails as a queued job that never picks up a runner, on a weekly
            # schedule nobody is watching.
            errors.append(
                f"{path.name}:{job} has runs-on: {runner} -- not an approved "
                "selector. This workflow is not PR-reachable, so the finding is "
                "about the LABELS, not fork trust: nothing else validates them "
                "(actionlint skips non-literal runs-on) and an unknown label is "
                "a job that never starts "
                "(see TRUST_SPLITS in ci/linter/workflow_policy.py)"
            )
    return report(
        "lint-ci-runners",
        errors,
        "fork PRs stay on hosted runners; trusted events reach self-hosted",
    )


# --------------------------------------------------------------------------
# ports


def _body(node: dict) -> str:
    """A job node re-serialised, for the substring questions asked below.

    The job SPLIT is structural (see jobs()); only the "does this job mention
    the driver / --port" questions are textual, and those are asked of this
    normalised dump rather than of the file. Two consequences, both wanted: a
    comment can no longer hide a job from the split -- `runtime: # note` used
    to yield ZERO jobs and a cheerful "no runtime-bearing jobs" -- and a port
    mentioned only in a comment no longer counts as a declaration.
    """
    return yaml.safe_dump(node, default_flow_style=False, sort_keys=False)


def _steps(node: dict) -> list[str]:
    """Each step's `run:` text, in declaration order. Non-run steps keep their
    slot as an empty string so an index comparison stays an ORDER comparison."""
    out: list[str] = []
    for step in node.get("steps") or []:
        if not isinstance(step, dict):
            out.append("")
            continue
        run = step.get("run")
        out.append(run if isinstance(run, str) else "")
    return out


def _order_finding(where: str, node: dict) -> str | None:
    """A band verifier that runs after something has already bound the band.

    The verify step is not a property of the job, it is a property of a
    POSITION: it can only speak for the steps below it. `build-test.yml` shipped
    it between `prove` and the runtime suite, which reads as guarded and left
    the first binder unguarded -- the failure max-port.sh exists to name still
    arrived inside `prove` as a bind error or a timeout with no cause attached.
    Only jobs that already carry the verifier are checked here; whether a
    binding job must carry one at all is the declaration check above.
    """
    runs = _steps(node)
    verify = next((i for i, r in enumerate(runs) if BAND_VERIFIER in r), None)
    if verify is None:
        return None
    first_bind = next((i for i, r in enumerate(runs) if BINDER_RE.search(r)), None)
    if first_bind is None or first_bind > verify:
        return None
    # Same step: a multi-line `run:` block may legitimately verify and then bind.
    # Index order cannot separate those, so fall back to position within the text.
    if first_bind == verify:
        run = runs[verify]
        if run.index(BAND_VERIFIER) < BINDER_RE.search(run).start():
            return None
        return (
            f"{where} binds the band earlier in the same step than it runs "
            f"{BAND_VERIFIER} (step {verify + 1}) -- verify first, then bind"
        )
    return (
        f"{where} runs {BAND_VERIFIER} at step {verify + 1}, after step "
        f"{first_bind + 1} has already bound the band -- the verifier only "
        "guards the steps below it, so move it above the FIRST binder"
    )


def check_ports() -> int:
    errors: list[str] = []
    bands: dict[str, str] = {}  # port value -> "file:job" that claimed it

    for path in workflows():
        doc = load(path)
        for job, node in jobs(doc):
            body = _body(node)
            declared = re.search(r"(?m)^\s*TEST_BASE_PORT:\s*[\"']?(\d+)", body)
            starts_runtime = RUNTIME_DRIVER in body
            where = f"{path.name}:{job}"

            order = _order_finding(where, node)
            if order:
                errors.append(order)

            # THE CHECK THAT MATTERS MOST. A new runtime-bearing job added later
            # with no band is invisible to the uniqueness check below (it
            # declares nothing to collide), silently takes the driver's default
            # --port, and reintroduces exactly the cross-job collision the bands
            # exist to prevent: two jobs pinned to the same runner, disjoint
            # concurrency groups, nothing serialising them, both binding 18880.
            if starts_runtime and not declared:
                errors.append(
                    f"{where} starts {RUNTIME_DRIVER} without declaring "
                    "TEST_BASE_PORT -- it would take the driver's default port "
                    "and collide with any other runtime job on the same runner"
                )
                continue

            if not declared:
                continue

            port = declared.group(1)
            if port in bands:
                errors.append(
                    f"{where} and {bands[port]} both claim TEST_BASE_PORT "
                    f"{port} -- bands must be disjoint across ALL workflows"
                )
            else:
                bands[port] = where

            # A declared band that is not passed through is decoration: the
            # driver still binds its default.
            if starts_runtime and "--port" not in body:
                errors.append(
                    f"{where} declares TEST_BASE_PORT but never passes --port; "
                    "the driver would bind its default anyway"
                )
            if starts_runtime and "TEST_BASE_PORT" not in body.split("--port")[-1][:40]:
                errors.append(
                    f"{where} passes --port with something other than "
                    "$TEST_BASE_PORT -- the declaration and the bind must be "
                    "the same value or they drift"
                )

    return report(
        "lint-ci-ports",
        errors,
        f"{len(bands)} runtime job(s), all with distinct port bands"
        if bands
        else "no runtime-bearing jobs",
    )


# --------------------------------------------------------------------------
# docs


def check_docs() -> int:
    """Every workflow is documented, and every documented workflow exists.

    The drift this catches is silent in both directions and neither direction
    fails anything else: a workflow added without a README row is a gate nobody
    knows exists (so nobody notices when it is later removed), and a README row
    for a deleted workflow is a badge that 404s and a claim of coverage the repo
    does not have. Structural facts only -- deliberately NOT exact job counts or
    durations, which are the brittle claims that get a drift check deleted.
    """
    errors: list[str] = []
    readme = ROOT / "README.md"
    if not readme.is_file():
        print("lint-docs-drift: no README.md", file=sys.stderr)
        return 2
    text = readme.read_text(encoding="utf-8")

    names = {p.name for p in workflows()}
    for name in sorted(names):
        if name not in text:
            errors.append(
                f"{name} exists under .github/workflows/ but is not mentioned "
                "in README.md -- an undocumented gate"
            )
    # Only PATH-QUALIFIED references. A bare "ci.yml" in prose could mean any
    # file; ".github/workflows/ci.yml" is unambiguously a claim that this repo
    # has that workflow, which is the claim worth checking.
    for ref in sorted(set(re.findall(r"\.github/workflows/([\w.-]+\.ya?ml)", text))):
        if ref not in names:
            errors.append(
                f"README.md references .github/workflows/{ref}, which does not "
                "exist -- a dead link or a stale badge"
            )
    return report(
        "lint-docs-drift",
        errors,
        f"{len(names)} workflow(s), all documented in README.md",
    )


COMMANDS = {
    "runners": check_runners,
    "ports": check_ports,
    "docs": check_docs,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in COMMANDS:
        print(f"usage: {argv[0]} {{{'|'.join(COMMANDS)}}}", file=sys.stderr)
        return 2
    if not WORKFLOWS.is_dir():
        print(f"no {WORKFLOWS} -- wrong tree?", file=sys.stderr)
        return 2
    try:
        return COMMANDS[argv[1]]()
    except PolicyError as exc:
        # 2, not 1: the check did not RUN. A workflow this file cannot parse is
        # also a workflow GitHub may read differently, so reporting "clean" or
        # even "findings" over the rest of the tree would be a claim the run
        # cannot support.
        print(f"workflow_policy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
