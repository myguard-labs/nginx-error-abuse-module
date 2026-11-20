#!/usr/bin/env python3
"""Replay all regressions and fuzz every discovered target; fail on omissions."""

import argparse
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def duration(value):
    if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 86400:
        raise argparse.ArgumentTypeError("duration must be 1..86400 decimal seconds")
    return value


# Admission allowances include both passes and the runner-specific job limit.
RUNNER_BUDGETS = {"github-hosted": 360 * 60, "self-hosted": 600 * 60}
JOB_OVERHEAD_SECONDS = 60 * 60  # setup, build, artifact upload and runner overhead
TARGET_OVERHEAD_SECONDS = 120 + 2 * 60 + 600  # regression, exit grace, minimization
REPLAY_SECONDS = 60  # per fixture, replayed once in each pass


def check_budget(root, seconds, runner_class="github-hosted"):
    duration(seconds)
    if runner_class not in RUNNER_BUDGETS:
        raise ValueError(f"unknown runner class: {runner_class}")
    budget = RUNNER_BUDGETS[runner_class]
    # Count source files so the workflow can reject excess before building.
    count = len(list(root.glob("fuzz_*.c")))
    if not count:
        raise ValueError("no fuzz targets discovered")
    replay_count = len(list((root / "regressions").glob("*.bin")))
    overhead = (
        JOB_OVERHEAD_SECONDS
        + count * TARGET_OVERHEAD_SECONDS
        + 2 * replay_count * REPLAY_SECONDS
    )
    required = overhead + count * int(seconds)
    if required > budget:
        maximum = max(0, (budget - overhead) // count)
        raise ValueError(
            f"total job budget exceeded: {required}s required for {count} targets "
            f"including regression and overhead; limit {budget}s; "
            f"maximum discovery duration is {maximum}s/target"
        )


def targets(root):
    result = {}
    for source in sorted(root.glob("fuzz_*.c")):
        name = source.stem.removeprefix("fuzz_")
        corpus = root / ("corpus" if name == "snapshot" else f"corpus_{name}")
        dictionary = root / ("fuzz.dict" if name == "statuses" else f"{name}.dict")
        binary = root / source.stem
        if not binary.is_file() or not corpus.is_dir():
            raise ValueError(
                f"missing fuzz binary or corpus for {name}: {binary}, {corpus}"
            )
        result[name] = (binary, corpus, dictionary)
    if not result:
        raise ValueError("no fuzz targets discovered")
    return result


def minimize(binary, corpus, root):
    minimized = corpus.with_name(corpus.name + "-min")
    workspace = Path(tempfile.mkdtemp(prefix=f".{minimized.name}-", dir=corpus.parent))
    pending = workspace / "new"
    previous = workspace / "previous"
    published = False
    artifacts = None
    try:
        pending.mkdir()
        artifacts = Path(
            tempfile.mkdtemp(prefix=f"crash-merge-{binary.name}-", dir=root)
        )
        subprocess.run(
            [
                str(binary),
                "-merge=1",
                str(pending),
                str(corpus),
                f"-artifact_prefix={artifacts}/",
            ],
            check=True,
            cwd=root,
        )
        # libFuzzer may retry a crashing merge worker and still exit zero.
        # Only this invocation's artifacts count; retain them for failure upload.
        if any(artifacts.iterdir()):
            raise OSError(f"merge produced crash artifacts: {artifacts}")
        if minimized.exists() or minimized.is_symlink():
            minimized.rename(previous)
        try:
            pending.rename(minimized)
        except OSError:
            if previous.exists() or previous.is_symlink():
                previous.rename(minimized)
            raise
        published = True
    finally:
        if artifacts is not None and not any(artifacts.iterdir()):
            artifacts.rmdir()
        # A failed rollback retains the previous corpus for recovery.
        if published or not (previous.exists() or previous.is_symlink()):
            shutil.rmtree(workspace)


def run(root, seconds, merge=False, runner_class="github-hosted"):
    check_budget(root, seconds, runner_class)
    selected = targets(root)
    # Validate all routing before replay or campaigns. The longest registered
    # prefix keeps overlapping, hyphenated target names unambiguous.
    names = sorted(selected, key=len, reverse=True)
    regressions = []
    for fixture in sorted((root / "regressions").glob("*.bin")):
        name = next(
            (name for name in names if fixture.name.startswith(f"{name}-")), None
        )
        if name is None or fixture.stem in selected or fixture.name == f"{name}-.bin":
            raise ValueError(f"regression has no target: {fixture.name}")
        regressions.append((selected[name][0], fixture))
    failures = []
    for binary, fixture in regressions:
        try:
            subprocess.run([str(binary), str(fixture)], check=True, cwd=root)
        except (OSError, subprocess.CalledProcessError) as exc:
            failures.append(exc)
    for binary, corpus, dictionary in selected.values():
        args = [
            str(binary),
            f"-max_total_time={seconds}",
            "-print_final_stats=1",
            f"-artifact_prefix={root}/crash-{binary.name}-",
        ]
        if dictionary.is_file():
            args.append(f"-dict={dictionary}")
        try:
            subprocess.run([*args, str(corpus)], check=True, cwd=root)
            if merge:
                minimize(binary, corpus, root)
        except (OSError, subprocess.CalledProcessError) as exc:
            failures.append(exc)
    if failures:
        raise failures[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seconds", type=duration)
    parser.add_argument("--merge", action="store_true")
    parser.add_argument(
        "--runner-class", choices=RUNNER_BUDGETS, default="github-hosted"
    )
    parser.add_argument(
        "--check-budget",
        action="store_true",
        help="validate the complete deep-job allowance from sources without running targets",
    )
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parent
        if args.check_budget:
            check_budget(root, args.seconds, args.runner_class)
        else:
            run(root, args.seconds, args.merge, args.runner_class)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"fuzz campaign failed: {exc}\n")


if __name__ == "__main__":
    main()
