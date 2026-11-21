#!/usr/bin/env python3
"""Regression controls for the PR88 full-review repairs."""

import contextlib
import re
import runpy
import shutil
import subprocess
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
                    self.assertEqual(not errors, valid, errors)

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
                            run.call_count,
                            3,
                            "fresh campaign ran after failed regression",
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


@contextlib.contextmanager
def tempfile_directory():
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        yield Path(directory)


if __name__ == "__main__":
    unittest.main()
