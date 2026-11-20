#!/usr/bin/env python3
"""Enforce CI04 cadence, retained gates and expanded four-runner bounds."""

import re
import sys
from itertools import pairwise
from pathlib import Path

import yaml
from check_ci_graph import GraphError, graph, width

ROOT = Path(__file__).resolve().parents[2]
PR_JOBS = {
    "build-test": {"validation", "build", "runtime", "coverage", "test-nginx"},
    "asan": {"asan", "asan-reload"},
    "valgrind": {"memcheck-lite"},
    "codeql": {"analyze"},
    "security-scanners": {"scanners"},
    "lint": {"lint"},
    "windows": {"mingw"},
}


def load(root, name):
    return yaml.safe_load((root / ".github/workflows" / name).read_text())


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
    errors = []
    pr = load(root, "ci.yml")
    deep = load(root, "ci-deep.yml")
    for entry in ("ci.yml", "ci-deep.yml"):
        if len(width(graph(root, ".github/workflows/" + entry))) > 4:
            errors.append(f"{entry}: fifth concurrent leaf")
    # Expand every call, including nested/matrix calls. A renamed caller cannot
    # hide fuzz or MSVC; command signatures also reject an inline transplant.
    leaves = graph(root)
    for path in sorted((root / ".github/workflows").glob("*.y*ml")):
        if path.name == "ci.yml":
            continue
        doc = yaml.safe_load(path.read_text())
        triggers = event_names(doc)
        if any(event in triggers for event in ("pull_request", "pull_request_target")):
            errors.append(f"additional PR entry point: {path.name}")
            # Also inspect every independently PR-reachable leaf, not only ci.yml.
            for leaf in graph(root, str(path.relative_to(root))):
                if re.search(r"fuzz|msvc", path.name + leaf, re.IGNORECASE):
                    errors.append(f"PR-reachable fuzz/MSVC: {path.name}/{leaf}")
    for leaf in leaves:
        parts = re.findall(r"([^/]+?)\[\d+\]", leaf)
        name = "ci.yml"
        for part in parts:
            job = load(root, name)["jobs"][part]
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
        if (
            job.get("uses") != expected
            or "if" in job
            and job["if"] != "${{ !cancelled() }}"
        ):
            errors.append(f"missing PR gate: {caller}")
        children = load(root, f"{caller}.yml")["jobs"]
        actual = set(children)
        if actual != required:
            errors.append(f"lost or unexpected PR target: {caller}: {actual}")
        for name in sorted(required & actual):
            if not healthy_pr_condition(caller, name, children[name]):
                errors.append(f"PR target cannot run on healthy PR: {caller}/{name}")
    events = deep.get("on", deep.get(True, {}))
    if (
        not isinstance(events, dict)
        or event_names(deep) != {"schedule", "workflow_dispatch"}
        or events.get("schedule") != [{"cron": "30 3 4 * *"}]
    ):
        errors.append("monthly/manual trigger contract")
    codeql = load(root, "codeql.yml")
    if "schedule" in event_names(codeql):
        errors.append("duplicate CodeQL schedule")
    jobs = deep["jobs"]
    if set(jobs) != {"fuzz", "msvc", "memcheck", "helgrind", "scanners", "codeql"}:
        errors.append("lost or unexpected monthly target")
    if jobs.get("msvc", {}).get("uses") != "./.github/workflows/windows-msvc.yml":
        errors.append("missing monthly MSVC")
    msvc = load(root, "windows-msvc.yml")["jobs"]
    required_steps = {
        "Build",
        "Verify module and configuration controls",
        "Test persistence and singleton ownership",
    }
    if set(msvc) != {"msvc"} or not required_steps <= {
        step.get("name") for step in msvc.get("msvc", {}).get("steps", [])
    }:
        errors.append("lost MSVC native control")
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
    if "FUZZ_SECS=3600" not in script(fuzz):
        errors.append("lost full fuzz duration")
    for name in ("memcheck", "helgrind"):
        if not re.search(
            r'ci/tools/soak.sh\s+\\\s+"[^"\n]+" 600 4', script(jobs.get(name, {}))
        ):
            errors.append(f"lost {name} full duration")
    if "pull_request" not in event_names(pr):
        errors.append("lost PR entry point")
    return errors


def main():
    try:
        errors = check(ROOT)
    except (GraphError, OSError, KeyError, TypeError, yaml.YAMLError) as exc:
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
