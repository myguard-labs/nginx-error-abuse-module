#!/usr/bin/env python3
"""Regression controls for the PR88 full-review repairs."""

import contextlib
import os
import re
import runpy
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import check_ci_cadence as cadence
import check_ci_graph as graph
import test_ci_cache_policy as cache_tests
import test_ci_cadence as cadence_tests
import test_ci_fuzz as fuzz_tests
import yaml


@contextlib.contextmanager
def fixture(kind):
    test = kind()
    test.setUp()
    try:
        yield test
    finally:
        test.doCleanups()


class ReviewRepairs(unittest.TestCase):
    def test_cache_path_survives_workspace_relocation(self):
        with (
            fixture(cache_tests.CompilerCachePreparation) as first,
            fixture(cache_tests.CompilerCachePreparation) as second,
        ):
            _, a = first.prepare()
            _, b = second.prepare()
            self.assertNotEqual(first.repo, second.repo)
            self.assertEqual(a["path"], b["path"])

    def test_exact_predecessors_accept_equivalent_scalar_and_list_forms(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/ci.yml"
            original = path.read_bytes()
            for name in cadence.PR_JOBS:
                doc = graph.load_workflow(path)
                job = doc["jobs"][name]
                needs = job.get("needs", [])
                if isinstance(needs, str):
                    job["needs"] = [needs]
                elif needs:
                    job["needs"] = list(reversed(needs))
                path.write_text(yaml.safe_dump(doc, sort_keys=False))
                self.assertEqual(cadence.check(test.root), [])
                if needs:
                    job["needs"] = []
                else:
                    job["needs"] = ["lint" if name == "build-test" else "build-test"]
                path.write_text(yaml.safe_dump(doc, sort_keys=False))
                self.assertIn(
                    f"PR predecessor contract: {name}", cadence.check(test.root)
                )
                path.write_bytes(original)

    def test_default_budget_boundary_tracks_target_and_fixture_inventory(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/ci-deep.yml"
            check_budget = runpy.run_path(str(test.root / "ci/fuzz/run.py"))[
                "check_budget"
            ]
            for add_target in (False, True):
                if add_target:
                    (test.root / "ci/fuzz/fuzz_extra.c").touch()
                with self.assertRaisesRegex(
                    ValueError, "maximum discovery duration"
                ) as error:
                    check_budget(test.root / "ci/fuzz", "86400")
                maximum = int(
                    re.search(
                        r"maximum discovery duration is ([0-9]+)", str(error.exception)
                    )[1]
                )
                for value, valid in ((maximum, True), (maximum + 1, False)):
                    doc = graph.load_workflow(path)
                    doc["on"]["workflow_dispatch"]["inputs"]["fuzz_seconds"][
                        "default"
                    ] = str(value)
                    path.write_text(yaml.safe_dump(doc, sort_keys=False))
                    errors = cadence.check(test.root)
                    manual = [
                        error
                        for error in errors
                        if "manual fuzz_seconds default" in error
                    ]
                    self.assertEqual(not manual, valid, errors)

    def test_callable_trigger_forms_and_standalone_entry(self):
        with tempfile_directory() as root:
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text(
                "on: pull_request\njobs:\n  call:\n    uses: ./.github/workflows/child.yml\n"
            )
            child = workflows / "child.yml"
            for events in (
                "workflow_call",
                ["workflow_call"],
                {"workflow_call": None},
                {"workflow_dispatch": None},
                None,
                False,
            ):
                with self.subTest(events=events):
                    child.write_text(
                        yaml.safe_dump(
                            {
                                "on": events,
                                "jobs": {"leaf": {"runs-on": "ubuntu-latest"}},
                            }
                        )
                    )
                    if (
                        events == "workflow_call"
                        or isinstance(events, (list, dict))
                        and "workflow_call" in events
                    ):
                        self.assertEqual(graph.graph(root), {"call[0]/leaf[0]": set()})
                    else:
                        with self.assertRaisesRegex(graph.GraphError, "workflow_call"):
                            graph.graph(root)

    def test_cache_path_matches_across_runner_slots(self):
        with fixture(cache_tests.CompilerCachePreparation) as test:
            _, first = test.prepare()
            other = test.root / "other runner"
            other.mkdir()
            _, second = test.prepare(RUNNER_TEMP=str(other))
            self.assertEqual(
                first["path"], second["path"], "runner slot changes cache version"
            )
            self.assertFalse(
                Path(first["path"]).is_absolute(),
                "service path must survive workspace relocation",
            )

    def test_min_target_corpus_seed_remains_addable(self):
        with tempfile_directory() as root:
            shutil.copyfile(cadence.ROOT / ".gitignore", root / ".gitignore")
            env = cadence_tests.fixture_environment()
            subprocess.run(
                ["git", "init", "-q", "--template="], cwd=root, env=env, check=True
            )
            for path, ignored in (
                ("ci/fuzz/corpus_headers-min/seed.bin", False),
                ("ci/fuzz/corpus_headers-min/0123456789abcdef", True),
                ("ci/fuzz/minimized/corpus_headers-min/seed.bin", True),
            ):
                with self.subTest(path=path):
                    result = subprocess.run(
                        [
                            "git",
                            "-c",
                            "core.excludesFile=/dev/null",
                            "check-ignore",
                            "--no-index",
                            "-q",
                            path,
                        ],
                        cwd=root,
                        env=env,
                        check=False,
                    )
                    self.assertEqual(result.returncode, int(not ignored), path)

    def test_merge_requires_completion_of_every_input(self):
        with fixture(fuzz_tests.FuzzTests) as test:
            corpus = test.root / "corpus"
            (corpus / "input.bin").write_bytes(b"input")
            old = test.root / "minimized/corpus"
            old.mkdir(parents=True)
            (old / "keep.bin").write_bytes(b"keep")
            for records in ("STARTED 0 5\n", "STARTED 0 5\nCOV 0 1\n"):
                (old / "keep.bin").write_bytes(b"keep")

                def merge(args, records=records, **kwargs):
                    control = Path(
                        next(
                            a.split("=", 1)[1]
                            for a in args
                            if a.startswith("-merge_control_file=")
                        )
                    )
                    control.write_text(f"1\n0\n{corpus / 'input.bin'}\n{records}")

                with (
                    self.subTest(records=records),
                    mock.patch.object(fuzz_tests.fuzz, "run_merge", side_effect=merge),
                    self.assertRaisesRegex(OSError, "every input"),
                ):
                    fuzz_tests.fuzz.minimize(
                        test.root / "fuzz_snapshot", corpus, test.root
                    )
                self.assertEqual((old / "keep.bin").read_bytes(), b"keep")

    def test_failed_replay_prevents_all_fresh_campaigns(self):
        with fixture(fuzz_tests.FuzzTests) as test:
            for error in (
                OSError("replay"),
                subprocess.CalledProcessError(7, "replay"),
                subprocess.TimeoutExpired("replay", 60),
            ):
                with (
                    self.subTest(error=type(error).__name__),
                    mock.patch.object(
                        fuzz_tests.fuzz.subprocess,
                        "run",
                        side_effect=[error, None, None, None, None, None],
                    ) as run,
                    self.assertRaises(type(error)),
                ):
                    try:
                        fuzz_tests.fuzz.run(test.root, "120")
                    finally:
                        self.assertEqual(
                            run.call_args_list,
                            [
                                mock.call(
                                    [
                                        str(test.root / f"fuzz_{name}"),
                                        str(
                                            test.root
                                            / f"regressions/{name}-boundary.bin"
                                        ),
                                    ],
                                    check=True,
                                    cwd=test.root,
                                    timeout=fuzz_tests.fuzz.REPLAY_SECONDS,
                                )
                                for name in ("accept", "snapshot", "statuses")
                            ],
                            "fresh campaign ran or a fixture replay was replaced",
                        )

    def test_staged_pathspec_overrides_cannot_hide_private_index(self):
        with fixture(cadence_tests.StagedCadenceTests) as test:
            test.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
            private = test.root / "private-index"
            shutil.copyfile(test.root / ".git/index", private)
            subprocess.run(
                ["git", "add", ".github/workflows/ci-deep.yml"],
                cwd=test.root,
                env=cadence_tests.fixture_environment(GIT_INDEX_FILE=str(private)),
                check=True,
            )
            for name in (
                "GIT_LITERAL_PATHSPECS",
                "GIT_GLOB_PATHSPECS",
                "GIT_NOGLOB_PATHSPECS",
                "GIT_ICASE_PATHSPECS",
            ):
                with self.subTest(name=name):
                    result = test.lint(
                        overrides={name: "1", "GIT_INDEX_FILE": str(private)}
                    )
                    self.assertEqual(
                        result.returncode, 1, result.stdout + result.stderr
                    )
                    self.assertIn(
                        b"lost full fuzz duration", result.stdout + result.stderr
                    )

    def test_pr_predecessors_cannot_be_extended(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/ci.yml"
            doc = graph.load_workflow(path)
            doc["jobs"]["windows"]["needs"].append("valgrind")
            path.write_text(yaml.safe_dump(doc, sort_keys=False))
            self.assertIn("PR predecessor contract: windows", cadence.check(test.root))

    def test_manual_default_must_fit_calculated_budget(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/ci-deep.yml"
            doc = graph.load_workflow(path)
            doc["on"]["workflow_dispatch"]["inputs"]["fuzz_seconds"]["default"] = (
                "86400"
            )
            path.write_text(yaml.safe_dump(doc, sort_keys=False))
            self.assertTrue(
                any(
                    "manual fuzz_seconds default exceeds runner budget" in error
                    for error in cadence.check(test.root)
                )
            )

    def test_every_callee_requires_workflow_call(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/windows.yml"
            doc = graph.load_workflow(path)
            del doc["on"]["workflow_call"]
            path.write_text(yaml.safe_dump(doc, sort_keys=False))
            with self.assertRaisesRegex(graph.GraphError, "workflow_call"):
                graph.graph(test.root)


class Cycle102Repairs(unittest.TestCase):
    def test_app72_workspace_rejected_before_prepare(self):
        with fixture(cache_tests.CompilerCachePreparation) as test:
            tools = test.repo / "ci/tools"
            (tools / "ci-build.sh").write_text(
                'echo called > "$GITHUB_OUTPUT.prepare"\n'
                'echo tree=fixture-executable-tree >> "$GITHUB_OUTPUT"\n'
                "echo expected-build-identity\n"
            )
            bad = test.root / "repo\n"
            shutil.copytree(test.repo, bad)
            test.repo = bad
            result, _ = test.prepare(success=False)
            self.assertIn("invalid workspace", result.stderr)
            self.assertFalse(Path(test.env["GITHUB_OUTPUT"] + ".prepare").exists())

    def test_app73_coverage_executable_cache_opt_out(self):
        action = yaml.safe_load(
            (cadence.ROOT / ".github/actions/build-cache/action.yml").read_text()
        )
        self.assertEqual(action["inputs"]["executable-cache"]["default"], "true")
        restore = next(
            s for s in action["runs"]["steps"] if s.get("id") == "executable"
        )
        self.assertIn("inputs.executable-cache == 'true'", restore["if"])
        workflow = graph.load_workflow(
            cadence.ROOT / ".github/workflows/build-test.yml"
        )
        cache = next(
            s
            for s in workflow["jobs"]["coverage"]["steps"]
            if s.get("uses") == "./.github/actions/build-cache"
        )
        self.assertEqual(cache["with"]["executable-cache"], "false")
        self.assertEqual(
            len(
                [
                    s
                    for s in action["runs"]["steps"]
                    if "actions/cache@" in s.get("uses", "")
                ]
            ),
            3,
        )

    def test_app74_reserved_target_suffix_docs(self):
        docs = (cadence.ROOT / "ci/fuzz/README.md").read_text(encoding="utf-8")
        self.assertIn("must not end in `.dict`, `.c`, or `.h`", docs)
        self.assertIn("fuzz_headers.v2.c", docs)

    def test_app75_seed_inventory_before_execution_and_before_publication(self):
        with fixture(fuzz_tests.FuzzTests) as test:
            corpus = test.root / "corpus"
            old = test.root / "minimized/corpus"
            old.mkdir(parents=True)
            (old / "keep").write_bytes(b"keep")
            for name in (".archive/input", "nested/.archive/input", "bad\nname"):
                seed = corpus / name
                seed.parent.mkdir(parents=True, exist_ok=True)
                seed.write_bytes(b"seed")
                with (
                    self.subTest(name=name),
                    mock.patch.object(fuzz_tests.fuzz.subprocess, "run") as run,
                    self.assertRaisesRegex(ValueError, "unsupported corpus seed"),
                ):
                    fuzz_tests.fuzz.run(test.root, "120")
                run.assert_not_called()
                seed.unlink()
            for name in ("nested/seed", ".visible-file"):
                seed = corpus / name
                seed.parent.mkdir(parents=True, exist_ok=True)
                seed.write_bytes(b"seed")
            (corpus / "empty").touch()
            seeds = [corpus / "nested/seed", corpus / ".visible-file"]
            for filenames, valid in (
                (seeds, True),
                (seeds[:1], False),
                ([seeds[0], seeds[0]], False),
                ([seeds[0], old / "keep"], False),
            ):

                def merge(args, filenames=filenames, **_kwargs):
                    control = Path(
                        next(
                            a.split("=", 1)[1]
                            for a in args
                            if a.startswith("-merge_control_file=")
                        )
                    )
                    records = b"".join(
                        b"STARTED %d 4\nFT %d\n" % (i, i) for i in range(len(filenames))
                    )
                    control.write_bytes(
                        str(len(filenames)).encode()
                        + b"\n0\n"
                        + b"".join(os.fsencode(p) + b"\n" for p in filenames)
                        + records
                    )

                with (
                    self.subTest(filenames=filenames),
                    mock.patch.object(fuzz_tests.fuzz, "run_merge", side_effect=merge),
                ):
                    if valid:
                        fuzz_tests.fuzz.minimize(
                            test.root / "fuzz_snapshot", corpus, test.root
                        )
                        (old / "keep").write_bytes(b"keep")
                    else:
                        with self.assertRaisesRegex(OSError, "every input"):
                            fuzz_tests.fuzz.minimize(
                                test.root / "fuzz_snapshot", corpus, test.root
                            )
                        self.assertEqual((old / "keep").read_bytes(), b"keep")

    def test_app76_interrupt_restores_vacant_corpus_and_retains_installed(self):
        for stage in ("after-backup", "before-install", "after-install"):
            with self.subTest(stage=stage), fixture(fuzz_tests.FuzzTests) as test:
                corpus = test.root / "corpus"
                old = test.root / "minimized/corpus"
                old.mkdir(parents=True)
                (old / "keep").write_bytes(b"keep")
                original = Path.rename

                def rename(path, destination, stage=stage, old=old, original=original):
                    if stage == "before-install" and path.name == "new":
                        raise KeyboardInterrupt
                    result = original(path, destination)
                    if (stage == "after-backup" and path == old) or (
                        stage == "after-install" and path.name == "new"
                    ):
                        raise KeyboardInterrupt
                    return result

                with (
                    mock.patch.object(fuzz_tests.fuzz, "run_merge"),
                    mock.patch.object(Path, "rename", new=rename),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    fuzz_tests.fuzz.minimize(
                        test.root / "fuzz_snapshot", corpus, test.root
                    )
                self.assertTrue(old.is_dir())
                if stage == "after-install":
                    self.assertEqual(list(old.iterdir()), [])
                else:
                    self.assertEqual((old / "keep").read_bytes(), b"keep")

    def test_app77_missing_deep_workflow_is_policy_finding(self):
        with fixture(cadence_tests.CadenceTests) as test:
            for name in ("README.md", "ci/fuzz/README.md"):
                target = test.root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(cadence.ROOT / name, target)
            (test.root / ".github/workflows/ci-deep.yml").unlink()
            result = subprocess.run(
                [
                    sys.executable,
                    str(cadence.ROOT / "ci/linter/workflow_policy.py"),
                    "docs",
                ],
                env=cadence_tests.fixture_environment(
                    WORKFLOW_POLICY_ROOT=str(test.root)
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertIn("missing ci-deep.yml", result.stdout + result.stderr)

    def test_app78_non_mapping_workflow_is_uncheckable(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/extra.yml"
            for value in ([], "text", 42, None):
                with self.subTest(value=value):
                    path.write_text(yaml.safe_dump(value))
                    with (
                        mock.patch.object(cadence, "ROOT", test.root),
                        mock.patch("sys.stderr"),
                    ):
                        self.assertEqual(cadence.main(), 2)
            for events in ("workflow_call", ["workflow_call"], {"workflow_call": None}):
                self.assertEqual(cadence.event_names({"on": events}), {"workflow_call"})

    def test_app79_upload_follows_every_scanner(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/ci-deep.yml"
            original = path.read_bytes()
            doc = graph.load_workflow(path)
            steps = doc["jobs"]["scanners"]["steps"]
            upload = next(s for s in steps if s.get("name") == "Upload reports")
            steps.remove(upload)
            for name in ("flawfinder", "clang-tidy (cert-*, security.*)", "semgrep"):
                index = next(i for i, s in enumerate(steps) if s.get("name") == name)
                steps.insert(index, upload)
                path.write_text(yaml.safe_dump(doc))
                self.assertIn(
                    "lost monthly scanner report upload", cadence.check(test.root)
                )
                steps.remove(upload)
            path.write_bytes(original)
            self.assertEqual(cadence.check(test.root), [])

    def test_app80_root_inclusive_ten_level_boundary(self):
        with tempfile_directory() as root:
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            for depth in (10, 11):
                for index in range(depth):
                    name = "ci.yml" if index == 0 else f"child{index}.yml"
                    job = (
                        {"uses": f"./.github/workflows/child{index + 1}.yml"}
                        if index < depth - 1
                        else {"runs-on": "ubuntu-latest"}
                    )
                    (workflows / name).write_text(
                        yaml.safe_dump({"on": "workflow_call", "jobs": {"next": job}})
                    )
                if depth == 10:
                    self.assertEqual(len(graph.graph(root)), 1)
                else:
                    with self.assertRaisesRegex(graph.GraphError, "nesting limit"):
                        graph.graph(root)


class Cycle103Repairs(unittest.TestCase):
    def test_app85_target_dictionary_routing(self):
        with fixture(fuzz_tests.FuzzTests) as test:
            (test.root / "fuzz_fuzz.c").touch()
            (test.root / "fuzz_fuzz").touch()
            (test.root / "corpus_fuzz").mkdir()
            for own in (False, True):
                with self.subTest(own=own):
                    if own:
                        (test.root / "fuzz_fuzz.dict").touch()
                    with mock.patch.object(fuzz_tests.fuzz.subprocess, "run") as run:
                        fuzz_tests.fuzz.run(test.root, "120")
                    calls = [c.args[0] for c in run.call_args_list]
                    status = next(
                        c
                        for c in calls
                        if c[0].endswith("fuzz_statuses") and "-max_total_time=120" in c
                    )
                    added = next(c for c in calls if c[0].endswith("fuzz_fuzz"))
                    self.assertIn(f"-dict={test.root}/fuzz.dict", status)
                    self.assertEqual(
                        [x for x in added if x.startswith("-dict=")],
                        [f"-dict={test.root}/fuzz_fuzz.dict"] if own else [],
                    )

    def test_app86_symlinked_input_root_rejected_before_execution(self):
        with fixture(fuzz_tests.FuzzTests) as test:
            corpus = test.root / "corpus_accept"
            published = test.root / "minimized/corpus_accept"
            published.mkdir(parents=True)
            (published / "keep").write_bytes(b"keep")
            corpus.rmdir()
            corpus.symlink_to(published, target_is_directory=True)
            for merge in (False, True):
                with (
                    self.subTest(merge=merge),
                    mock.patch.object(fuzz_tests.fuzz.subprocess, "run") as run,
                ):
                    with self.assertRaisesRegex(ValueError, "corpus root.*symlink"):
                        fuzz_tests.fuzz.run(test.root, "120", merge)
                    run.assert_not_called()
            with mock.patch.object(fuzz_tests.fuzz, "run_merge") as run:
                with self.assertRaisesRegex(ValueError, "corpus root.*symlink"):
                    fuzz_tests.fuzz.minimize(
                        test.root / "fuzz_accept", corpus, test.root
                    )
                run.assert_not_called()
            self.assertEqual((published / "keep").read_bytes(), b"keep")

    def test_app87_deep_nested_mappings_are_policy_findings(self):
        with fixture(cadence_tests.WorkflowFixture) as test:
            for name in ("README.md", "ci/fuzz/README.md"):
                target = test.root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(cadence.ROOT / name, target)
            path = test.root / ".github/workflows/ci-deep.yml"
            for jobs in ([], None, {"fuzz": []}, {"fuzz": None}):
                with self.subTest(jobs=jobs):
                    path.write_text(yaml.safe_dump({"jobs": jobs}), encoding="utf-8")
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(cadence.ROOT / "ci/linter/workflow_policy.py"),
                            "docs",
                        ],
                        env=cadence_tests.fixture_environment(
                            WORKFLOW_POLICY_ROOT=str(test.root)
                        ),
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode, 1, result.stdout + result.stderr
                    )
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertIn("must be a mapping", result.stdout + result.stderr)

    def test_app88_runtime_cannot_suppress_failures(self):
        with fixture(cadence_tests.WorkflowFixture) as test:
            path = test.root / ".github/workflows/build-test.yml"
            original = path.read_bytes()
            for value in (True, "false", "${{ true }}", False, None):
                with self.subTest(value=value):
                    path.write_bytes(original)
                    doc = graph.load_workflow(path)
                    if value is not None:
                        doc["jobs"]["runtime"]["continue-on-error"] = value
                    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                    errors = cadence.check(test.root)
                    if value is False or value is None:
                        self.assertEqual(errors, [])
                    else:
                        self.assertIn(
                            "required runtime job can suppress failure", errors
                        )

    def test_app89_missing_basic_job_reports_policy_finding(self):
        with fixture(cadence_tests.WorkflowFixture) as test:
            path = test.root / ".github/workflows/build-test.yml"
            doc = graph.load_workflow(path)
            del doc["jobs"]["test-nginx"]
            for job in doc["jobs"].values():
                needs = job.get("needs", [])
                if isinstance(needs, str):
                    needs = [needs]
                if "test-nginx" in needs:
                    job["needs"] = [name for name in needs if name != "test-nginx"]
            path.write_text(yaml.safe_dump(doc), encoding="utf-8")
            errors = cadence.check(test.root)
            self.assertTrue(
                any("lost or unexpected PR target: build-test" in e for e in errors)
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import check_ci_cadence as p; from pathlib import Path; "
                    + f"p.ROOT = Path({str(test.root)!r}); raise SystemExit(p.main())",
                ],
                env=cadence_tests.fixture_environment(
                    PYTHONPATH=str(cadence.ROOT / "ci/tools")
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_app90_duration_cannot_change_after_selection(self):
        with fixture(cadence_tests.WorkflowFixture) as test:
            path = test.root / ".github/workflows/ci-deep.yml"
            original = path.read_bytes()
            for command in (
                'echo "FUZZ_SECS=60" >> "$GITHUB_ENV"',
                'printf "FUZZ_SECS=60\\n" | tee -a "$GITHUB_ENV"',
                'echo "FUZZ_SECS=60" | tee --append "$GITHUB_ENV"',
                'echo "FUZZ_SECS=60" >> "${GITHUB_ENV}"',
                'echo "FUZZ_SECS=60 >> "$GITHUB_ENV"',
            ):
                with self.subTest(command=command):
                    path.write_bytes(original)
                    doc = graph.load_workflow(path)
                    steps = doc["jobs"]["fuzz"]["steps"]
                    index = next(
                        i
                        for i, step in enumerate(steps)
                        if "--check-budget" in str(step.get("run"))
                    )
                    steps.insert(index + 1, {"run": command})
                    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                    self.assertIn(
                        "fuzz duration changed after selection",
                        cadence.check(test.root),
                    )
            for command in (
                'echo "$FUZZ_SECS"\necho "CACHE_HIT=true" >> "$GITHUB_ENV"',
                'echo "$FUZZ_SECS"; echo "CACHE_HIT=true" >> "$GITHUB_ENV"',
                '# echo "FUZZ_SECS=60" >> "$GITHUB_ENV"',
                'echo "FUZZ_SECS=60"',
                'echo "NOT_FUZZ_SECS=60" >> "$GITHUB_ENV"',
                'echo "$FUZZ_SECS" | cat "$GITHUB_ENV"',
            ):
                with self.subTest(harmless=command):
                    path.write_bytes(original)
                    doc = graph.load_workflow(path)
                    steps = doc["jobs"]["fuzz"]["steps"]
                    index = next(
                        i
                        for i, step in enumerate(steps)
                        if "--check-budget" in str(step.get("run"))
                    )
                    steps.insert(index + 1, {"run": command})
                    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                    self.assertEqual(cadence.check(test.root), [])
            path.write_bytes(original)
            self.assertEqual(cadence.check(test.root), [])

    def test_app92_utf8_fixtures_under_ascii_locale(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "test_ci_review_policy.CadenceRepairTests.test_app70_monthly_scanners_and_report_upload_required",
            ],
            cwd=cadence.ROOT,
            env=cadence_tests.fixture_environment(
                LC_ALL="C",
                PYTHONUTF8="0",
                PYTHONCOERCECLOCALE="0",
                PYTHONPATH=str(cadence.ROOT / "ci/tools"),
            ),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class Cycle104Repairs(unittest.TestCase):
    def test_app94_unreadable_seed_fails_before_campaign(self):
        with fixture(fuzz_tests.FuzzTests) as test:
            seed = test.root / "corpus/input.bin"
            seed.write_bytes(b"input")
            original = Path.open

            def open_seed(path, *args, **kwargs):
                if path == seed:
                    raise PermissionError("unreadable seed control")
                return original(path, *args, **kwargs)

            for merge in (False, True):
                with (
                    self.subTest(merge=merge),
                    mock.patch.object(Path, "open", open_seed),
                    mock.patch.object(fuzz_tests.fuzz.subprocess, "run") as run,
                    self.assertRaisesRegex(PermissionError, "unreadable seed control"),
                ):
                    fuzz_tests.fuzz.run(test.root, "120", merge)
                run.assert_not_called()
            seed.unlink()
            self.assertEqual(fuzz_tests.fuzz.corpus_inputs(seed.parent), set())

    def test_app95_oversized_seed_fails_before_campaign(self):
        with fixture(fuzz_tests.FuzzTests) as test:
            seed = test.root / "corpus/input.bin"
            seed.write_bytes(b"A" * (1 << 20))
            self.assertEqual(
                fuzz_tests.fuzz.corpus_inputs(seed.parent), {os.fsencode(seed)}
            )
            seed.write_bytes(b"A" * ((1 << 20) + 1))
            for merge in (False, True):
                with (
                    self.subTest(merge=merge),
                    mock.patch.object(fuzz_tests.fuzz.subprocess, "run") as run,
                    self.assertRaisesRegex(ValueError, "corpus seed exceeds.*1048576"),
                ):
                    fuzz_tests.fuzz.run(test.root, "120", merge)
                run.assert_not_called()

    def test_app95_merge_requires_full_tested_size(self):
        with fixture(fuzz_tests.FuzzTests) as test:
            corpus = test.root / "corpus"
            seed = corpus / "input.bin"
            seed.write_bytes(b"input")
            old = test.root / "minimized/corpus"
            old.mkdir(parents=True)
            (old / "keep").write_bytes(b"keep")
            for size in (0, 4, 6, 5):

                def merge(args, size=size, **_kwargs):
                    control = Path(
                        next(
                            a.split("=", 1)[1]
                            for a in args
                            if a.startswith("-merge_control_file=")
                        )
                    )
                    control.write_bytes(
                        b"1\n0\n"
                        + os.fsencode(seed)
                        + f"\nSTARTED 0 {size}\nFT 0\n".encode()
                    )

                with mock.patch.object(fuzz_tests.fuzz, "run_merge", side_effect=merge):
                    if size == 5:
                        fuzz_tests.fuzz.minimize(
                            test.root / "fuzz_snapshot", corpus, test.root
                        )
                        self.assertEqual(list(old.iterdir()), [])
                    else:
                        with self.assertRaisesRegex(OSError, "malformed control"):
                            fuzz_tests.fuzz.minimize(
                                test.root / "fuzz_snapshot", corpus, test.root
                            )
                        self.assertEqual((old / "keep").read_bytes(), b"keep")

    def test_app96_asan_upload_requires_binary_and_missing_file_error(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/asan.yml"
            original = path.read_bytes()
            for inputs in (
                None,
                [],
                {},
                {"path": "missing", "if-no-files-found": "warn"},
                {"path": ".build/asan-artifact/nginx", "if-no-files-found": "warn"},
                {"path": "missing", "if-no-files-found": "error"},
            ):
                doc = graph.load_workflow(path)
                upload = next(
                    s
                    for s in doc["jobs"]["asan"]["steps"]
                    if s.get("id") == "asan-artifact"
                )
                upload["with"] = inputs
                path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                self.assertIn(
                    "lost ASan artifact upload step", cadence.check(test.root)
                )
                path.write_bytes(original)
            self.assertEqual(cadence.check(test.root), [])

    def test_app97_manual_duration_is_free_entry(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/ci-deep.yml"
            original = path.read_bytes()
            for kind, valid in (
                ("choice", False),
                ("boolean", False),
                ("environment", False),
                ("number", False),
                ("string", True),
                (None, True),
            ):
                doc = graph.load_workflow(path)
                value = doc["on"]["workflow_dispatch"]["inputs"]["fuzz_seconds"]
                if kind is not None:
                    value["type"] = kind
                if kind == "choice":
                    value["options"] = ["3600"]
                path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                self.assertEqual(
                    "manual fuzz_seconds must allow free entry"
                    in cadence.check(test.root),
                    not valid,
                )
                path.write_bytes(original)

    def test_app98_scanner_upload_inputs_require_mapping(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/ci-deep.yml"
            original = path.read_bytes()
            for value in (None, [], "reports", {}):
                doc = graph.load_workflow(path)
                next(
                    s
                    for s in doc["jobs"]["scanners"]["steps"]
                    if s.get("name") == "Upload reports"
                )["with"] = value
                path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                self.assertIn(
                    "lost monthly scanner report upload", cadence.check(test.root)
                )
                path.write_bytes(original)
            self.assertEqual(cadence.check(test.root), [])

    def test_app99_minimized_upload_enabled_after_discovery(self):
        with fixture(cadence_tests.CadenceTests) as test:
            path = test.root / ".github/workflows/ci-deep.yml"
            original = path.read_bytes()
            for mutation in (
                "disabled",
                "missing",
                "action",
                "path",
                "inputs",
                "early",
                "suppressed",
                "valid",
            ):
                doc = graph.load_workflow(path)
                steps = doc["jobs"]["fuzz"]["steps"]
                upload = next(
                    s for s in steps if s.get("name") == "Upload minimized corpus"
                )
                if mutation == "disabled":
                    upload["if"] = False
                if mutation == "missing":
                    steps.remove(upload)
                if mutation == "action":
                    upload["uses"] = "actions/download-artifact@fake"
                if mutation == "path":
                    upload["with"]["path"] = "ci/fuzz/corpus"
                if mutation == "inputs":
                    upload["with"] = None
                if mutation == "suppressed":
                    upload["continue-on-error"] = True
                if mutation == "early":
                    steps.remove(upload)
                    steps.insert(0, upload)
                path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                self.assertEqual(
                    "lost minimized corpus upload after discovery"
                    in cadence.check(test.root),
                    mutation != "valid",
                )
                path.write_bytes(original)

    def test_app100_nested_reusable_workflow_rejected(self):
        with tempfile_directory() as root:
            workflows = root / ".github/workflows"
            (workflows / "nested").mkdir(parents=True)
            child = {
                "on": "workflow_call",
                "jobs": {"leaf": {"runs-on": "ubuntu-latest"}},
            }
            for target, valid in (("nested/child.yml", False), ("child.yml", True)):
                (workflows / target).write_text(yaml.safe_dump(child), encoding="utf-8")
                (workflows / "ci.yml").write_text(
                    yaml.safe_dump(
                        {"jobs": {"call": {"uses": "./.github/workflows/" + target}}}
                    ),
                    encoding="utf-8",
                )
                if valid:
                    self.assertEqual(graph.graph(root), {"call[0]/leaf[0]": set()})
                else:
                    with self.assertRaisesRegex(
                        graph.GraphError, "unsupported reusable workflow"
                    ):
                        graph.graph(root)

    def test_app103_fuzz_readme_under_ascii_locale(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "test_pr88_review.Cycle102Repairs.test_app74_reserved_target_suffix_docs",
            ],
            cwd=cadence.ROOT,
            env=cadence_tests.fixture_environment(
                LC_ALL="C",
                PYTHONUTF8="0",
                PYTHONCOERCECLOCALE="0",
                PYTHONPATH=str(cadence.ROOT / "ci/tools"),
            ),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@contextlib.contextmanager
def tempfile_directory():
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        yield Path(directory)


if __name__ == "__main__":
    unittest.main()
