#!/usr/bin/env python3
"""Enforce CI04 cadence, retained gates and expanded four-runner bounds."""

import re
import sys
from itertools import pairwise
from pathlib import Path

import yaml
from check_ci_graph import GraphError, graph, load_workflow, width

ROOT = Path(__file__).resolve().parents[2]
PR_JOBS = {
    "build-test": {
        "validation",
        "build",
        "runtime",
        "coverage",
        "test-nginx",
        "snapshot-controls",
    },
    "asan": {"asan", "asan-reload"},
    "valgrind": {"memcheck-lite"},
    "codeql": {"analyze"},
    "security-scanners": {"scanners"},
    "lint": {"lint"},
    "windows": {"mingw"},
}


def load(root, name):
    return load_workflow(root / ".github/workflows" / name)


def event_names(doc):
    events = doc.get("on", doc.get(True, {}))
    if isinstance(events, str):
        return {events}
    if isinstance(events, (list, dict)) and all(
        isinstance(event, str) for event in events
    ):
        return set(events)
    raise TypeError("workflow events must be a name, a list of names or a mapping")


def script(job):
    return "\n".join(str(step.get("run", "")) for step in job.get("steps", []))


def healthy_pr_condition(caller, name, job):
    condition = str(job.get("if", "success()"))
    condition = condition.removeprefix("${{").removesuffix("}}").strip()
    return condition in {"success()", "always()", "!cancelled()"} or (
        (caller, name) == ("asan", "asan-reload")
        and job.get("needs") in ("asan", ["asan"])
        and condition == "!cancelled() && needs.asan.outputs.artifact-id != ''"
    )


def healthy_fuzz_step_condition(step, *, success_only=False):
    """Recognize a bounded healthy-run grammar, not every Actions expression."""
    condition = step.get("if", "success()")
    if isinstance(condition, bool):
        return condition
    if not isinstance(condition, str):
        return False
    condition = condition.strip()
    if condition.startswith("${{") and condition.endswith("}}"):
        condition = condition[3:-2].strip()
    # Permit redundant grouping around a single supported status/literal.
    while condition.startswith("(") and condition.endswith(")"):
        condition = condition[1:-1].strip()
    pattern = r"success\s*\(\s*\)|true"
    if not success_only:
        pattern += r"|always\s*\(\s*\)|!\s*cancelled\s*\(\s*\)"
    return (
        re.fullmatch(
            pattern,
            condition,
            re.IGNORECASE,
        )
        is not None
    )


def check(root):
    # Documents live only for this invocation; traversal and validation still run
    # for every call. Failed reads/parses never enter the cache.
    documents = {}

    def document(path):
        key = path.resolve()
        if key not in documents:
            documents[key] = load_workflow(path)
        return documents[key]

    def workflow(name):
        return document(root / ".github/workflows" / name)

    errors = []
    pr = workflow("ci.yml")
    deep = workflow("ci-deep.yml")
    for entry in ("ci.yml", "ci-deep.yml"):
        expanded = graph(root, ".github/workflows/" + entry, document_loader=document)
        if len(width(expanded)) > 4:
            errors.append(f"{entry}: fifth concurrent leaf")
    # Expand every call, including nested/matrix calls. A renamed caller cannot
    # hide fuzz or MSVC; command signatures also reject an inline transplant.
    leaves = graph(root, document_loader=document)
    for path in sorted((root / ".github/workflows").glob("*.y*ml")):
        doc = document(path)
        triggers = event_names(doc)
        if "schedule" in triggers and path.name not in {"ci-deep.yml", "codeql.yml"}:
            errors.append(f"additional scheduled entry point: {path.name}")
        if path.name == "ci.yml":
            continue
        if any(event in triggers for event in ("pull_request", "pull_request_target")):
            errors.append(f"additional PR entry point: {path.name}")
            # Also inspect every independently PR-reachable leaf, not only ci.yml.
            for leaf in graph(
                root, str(path.relative_to(root)), document_loader=document
            ):
                if re.search(r"fuzz|msvc", path.name + leaf, re.IGNORECASE):
                    errors.append(f"PR-reachable fuzz/MSVC: {path.name}/{leaf}")
    for leaf in leaves:
        parts = re.findall(r"([^/]+?)\[\d+\]", leaf)
        name = "ci.yml"
        for part in parts:
            job = workflow(name)["jobs"][part]
            if "uses" in job:
                name = Path(job["uses"]).name
        if re.search(r"fuzz|msvc", leaf + name, re.IGNORECASE) or re.search(
            r"ci/fuzz/(?:build.sh|run.py)|fuzz_(?:snapshot|statuses|accept)|nmake|vcvars|with-cc=cl",
            script(job),
            re.IGNORECASE,
        ):
            errors.append(f"PR-reachable fuzz/MSVC: {leaf}")
    for caller, required in PR_JOBS.items():
        job = pr["jobs"].get(caller, {})
        expected = f"./.github/workflows/{caller}.yml"
        # build-test is named the same as its caller; no conditional green stub.
        entry = caller in {"build-test", "lint"}
        if job.get("uses") != expected or (
            (not entry or "if" in job) and job.get("if") != "${{ !cancelled() }}"
        ):
            errors.append(f"missing PR gate: {caller}")
        if caller in {"build-test", "lint"} and "needs" in job:
            errors.append(f"PR entry job cannot depend on other jobs: {caller}")
        children = workflow(f"{caller}.yml")["jobs"]
        actual = set(children)
        if actual != required:
            errors.append(f"lost or unexpected PR target: {caller}: {actual}")
        for name in sorted(required & actual):
            if not healthy_pr_condition(caller, name, children[name]):
                errors.append(f"PR target cannot run on healthy PR: {caller}/{name}")
    basic = [
        step
        for step in workflow("build-test.yml")["jobs"]["test-nginx"].get("steps", [])
        if step.get("name") == "Run ci/t/basic.t"
    ]
    if len(basic) != 1 or basic[0].get("continue-on-error", False) is not False:
        errors.append("required basic.t step can suppress failure")
    if len(basic) == 1 and not healthy_fuzz_step_condition(basic[0]):
        errors.append("required basic.t step cannot run")
    events = deep.get("on", deep.get(True, {}))
    if (
        not isinstance(events, dict)
        or event_names(deep) != {"schedule", "workflow_dispatch"}
        or events.get("schedule") != [{"cron": "30 3 4 * *"}]
    ):
        errors.append("monthly/manual trigger contract")
    codeql = workflow("codeql.yml")
    if "schedule" in event_names(codeql):
        errors.append("duplicate CodeQL schedule")
    jobs = deep["jobs"]
    if set(jobs) != {"fuzz", "msvc", "memcheck", "helgrind", "scanners", "codeql"}:
        errors.append("lost or unexpected monthly target")
    if jobs.get("msvc", {}).get("uses") != "./.github/workflows/windows-msvc.yml":
        errors.append("missing monthly MSVC")
    msvc = workflow("windows-msvc.yml")["jobs"]
    required_steps = {
        "Build",
        "Verify module and configuration controls",
        "Test persistence and singleton ownership",
    }
    if set(msvc) != {"msvc"} or not required_steps <= {
        step.get("name") for step in msvc.get("msvc", {}).get("steps", [])
    }:
        errors.append("lost MSVC native control")
    for step in msvc.get("msvc", {}).get("steps", []):
        if step.get("name") in required_steps and not healthy_fuzz_step_condition(step):
            errors.append(f"MSVC native control cannot run: {step['name']}")
    for job, predecessor in (("memcheck", "msvc"), ("codeql", "scanners")):
        if (
            jobs.get(job, {}).get("needs") != predecessor
            or jobs[job].get("if") != "${{ !cancelled() }}"
        ):
            errors.append(f"monthly ordering/diagnostics: {job}")
    if jobs.get("codeql", {}).get("uses") != "./.github/workflows/codeql.yml":
        errors.append("lost monthly CodeQL")
    fuzz = jobs.get("fuzz", {})
    if "continue-on-error" in fuzz and fuzz["continue-on-error"] is not False:
        errors.append("fuzz job can suppress failure")
    if not healthy_fuzz_step_condition(fuzz):
        errors.append("fuzz job cannot run on healthy monthly run")
    commands = [step.get("run") for step in fuzz.get("steps", [])]
    build = 'bash ci/fuzz/build.sh "$GITHUB_WORKSPACE/ci/fuzz"'
    preflight = 'python3 ci/fuzz/run.py "$FUZZ_SECS" --runner-class "$RUNNER_ENVIRONMENT" --check-budget'
    regression = 'python3 ci/fuzz/run.py 120 --runner-class "$RUNNER_ENVIRONMENT"'
    discovery = 'python3 ci/fuzz/run.py "$FUZZ_SECS" --merge --runner-class "$RUNNER_ENVIRONMENT"'
    required_fuzz = (preflight, build, regression, discovery)
    if any(commands.count(command) != 1 for command in required_fuzz) or (
        all(command in commands for command in required_fuzz)
        and any(
            commands.index(first) > commands.index(second)
            for first, second in pairwise(required_fuzz)
        )
    ):
        errors.append("lost fuzz regression/discovery or shared build")
    for step in fuzz.get("steps", []):
        if (
            step.get("run") in required_fuzz
            and "continue-on-error" in step
            and step["continue-on-error"] is not False
        ):
            errors.append(f"fuzz step can suppress failure: {step['run']}")
        if step.get("run") in required_fuzz and not healthy_fuzz_step_condition(
            step, success_only=step.get("run") == discovery
        ):
            errors.append(f"fuzz step cannot run on healthy monthly run: {step['run']}")
        if step.get("run") in {preflight, discovery} and "FUZZ_SECS" in step.get(
            "env", {}
        ):
            errors.append("fuzz phase overrides selected duration")
    # This is a deliberately bounded shell contract, not a shell interpreter.
    # Match the selector's final scheduled branch and its actual environment
    # write; comments and literals elsewhere cannot satisfy the contract.
    selectors = [
        step
        for step in fuzz.get("steps", [])
        if step.get("name") == "Select fuzz duration"
    ]
    selection = (
        "\n".join(
            line.strip()
            for line in str(selectors[0].get("run", "")).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        if len(selectors) == 1
        else ""
    )
    if not re.fullmatch(
        r'set -euo pipefail\nif \[ "\$EVENT_NAME" = "workflow_dispatch" \]; then\n'
        r'.*\nelse\nprintf \'FUZZ_SECS=3600\\n\' >> "\$GITHUB_ENV"\nfi',
        selection,
        re.DOTALL,
    ) or not healthy_fuzz_step_condition(selectors[0]):
        errors.append("lost full fuzz duration")
    if (
        len(selectors) == 1
        and preflight in commands
        and fuzz["steps"].index(selectors[0]) > commands.index(preflight)
    ):
        errors.append("fuzz duration selected after budget preflight")
    for name, variable in (("memcheck", "USE_VALGRIND"), ("helgrind", "USE_HELGRIND")):
        soaks = [
            step
            for step in jobs.get(name, {}).get("steps", [])
            if re.search(
                r'^bash ci/tools/soak\.sh \\\n[ \t]*"[^"\n]+" 600 4[ \t]*$',
                str(step.get("run", "")),
                re.MULTILINE,
            )
        ]
        if not soaks:
            errors.append(f"lost {name} full duration")
        for step in soaks:
            if step.get("env", {}).get(variable) != "1":
                errors.append(f"lost {name} instrumentation")
            if not healthy_fuzz_step_condition(step):
                errors.append(f"{name} soak cannot run on healthy monthly run")
    for event in event_names(pr) - {"pull_request", "workflow_dispatch"}:
        errors.append(f"unexpected PR entry point: {event}")
    if "pull_request" not in event_names(pr):
        errors.append("lost PR entry point")
    elif not isinstance(pr.get("on"), dict) or pr["on"]["pull_request"] != {
        "branches": ["main"]
    }:
        errors.append("PR trigger must target main without filters")
    return errors


def main():
    try:
        errors = check(ROOT)
    except (
        GraphError,
        OSError,
        UnicodeError,
        KeyError,
        TypeError,
        yaml.YAMLError,
    ) as exc:
        print(f"CI cadence cannot be checked: {exc}", file=sys.stderr)
        return 2
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print(
            "CI cadence: retained PR gates; monthly/manual campaigns; both widths <= 4"
        )
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
