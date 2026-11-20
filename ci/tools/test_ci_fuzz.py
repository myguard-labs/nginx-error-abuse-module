#!/usr/bin/env python3
"""Fuzz orchestration controls, including a bounded real ASan merge probe."""

import argparse
import importlib.util
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

SPEC = importlib.util.spec_from_file_location(
    "fuzz_runner", Path(__file__).resolve().parents[1] / "fuzz/run.py"
)
if SPEC is None or SPEC.loader is None:
    raise ImportError("unable to load fuzz runner")
fuzz = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fuzz)


class FuzzTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "regressions").mkdir()
        for name in ("snapshot", "statuses", "accept"):
            (self.root / f"fuzz_{name}.c").touch()
            (self.root / f"fuzz_{name}").touch()
            (self.root / ("corpus" if name == "snapshot" else f"corpus_{name}")).mkdir()
            (self.root / f"regressions/{name}-boundary.bin").touch()
        (self.root / "fuzz.dict").touch()

    def test_all_targets_replay_full_duration_dictionary_and_merge(self):
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "3600", True)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(calls), 9)
        for name in ("snapshot", "statuses", "accept"):
            self.assertTrue(
                any(
                    args[0].endswith(f"fuzz_{name}") and "-max_total_time=3600" in args
                    for args in calls
                )
            )
            self.assertTrue(
                any(
                    args[0].endswith(f"fuzz_{name}")
                    and args[-1].endswith(f"{name}-boundary.bin")
                    for args in calls
                )
            )
            self.assertTrue(
                any(
                    args[0].endswith(f"fuzz_{name}") and "-merge=1" in args
                    for args in calls
                )
            )
        status = next(
            args
            for args in calls
            if "-max_total_time=3600" in args and args[0].endswith("statuses")
        )
        self.assertIn(f"-dict={self.root}/fuzz.dict", status)
        self.assertTrue(all(call.kwargs["check"] for call in run.call_args_list))

    def test_minimization_replaces_stale_output_from_empty_unique_workspace(self):
        corpora = ("corpus", "corpus_accept", "corpus_statuses")
        for name in corpora:
            (self.root / name / "input.bin").write_bytes(b"input")
            minimized = self.root / f"{name}-min"
            (minimized / "nested").mkdir(parents=True)
            (minimized / "nested/stale.bin").write_bytes(b"stale")
        expected_paths = set(self.root.iterdir())
        destinations = []
        for payload in (b"first", b"second"):

            def execute(args, *, check, cwd, payload=payload):
                self.assertTrue(check)
                self.assertEqual(cwd, self.root)
                if "-merge=1" in args:
                    pending, corpus = map(Path, args[2:4])
                    self.assertEqual(list(pending.iterdir()), [])
                    self.assertEqual(pending.parent.parent, self.root)
                    self.assertNotEqual(pending, corpus.with_name(corpus.name + "-min"))
                    self.assertEqual((corpus / "input.bin").read_bytes(), b"input")
                    destinations.append(pending)
                    (pending / "fresh.bin").write_bytes(payload)

            with mock.patch.object(fuzz.subprocess, "run", side_effect=execute) as run:
                fuzz.run(self.root, "120", True)
            self.assertEqual(run.call_count, 9)
            for name in corpora:
                minimized = self.root / f"{name}-min"
                self.assertEqual(list(minimized.iterdir()), [minimized / "fresh.bin"])
                self.assertEqual((minimized / "fresh.bin").read_bytes(), payload)
            self.assertEqual(set(self.root.iterdir()), expected_paths)
        self.assertEqual(len(set(destinations)), 6)

    def test_minimization_can_publish_empty_output_without_previous_corpus(self):
        expected_paths = set(self.root.iterdir())
        with mock.patch.object(fuzz.subprocess, "run"):
            fuzz.run(self.root, "120", True)
        for name in ("corpus", "corpus_accept", "corpus_statuses"):
            minimized = self.root / f"{name}-min"
            expected_paths.add(minimized)
            self.assertTrue(minimized.is_dir())
            self.assertEqual(list(minimized.iterdir()), [])
        self.assertEqual(set(self.root.iterdir()), expected_paths)

    def test_minimization_failure_preserves_previous_corpus_and_continues(self):
        minimized = self.root / "corpus_accept-min"
        minimized.mkdir()
        (minimized / "previous.bin").write_bytes(b"previous")
        for error in (
            subprocess.CalledProcessError(17, "merge"),
            OSError("merge could not start"),
        ):
            with self.subTest(error=type(error).__name__):

                def execute(args, error=error, **_kwargs):
                    if "-merge=1" in args:
                        pending = Path(args[2])
                        self.assertEqual(list(pending.iterdir()), [])
                        (pending / "partial.bin").write_bytes(b"partial")
                        if Path(args[0]).name == "fuzz_accept":
                            self.assertEqual(
                                (minimized / "previous.bin").read_bytes(), b"previous"
                            )
                            raise error

                with (
                    mock.patch.object(
                        fuzz.subprocess, "run", side_effect=execute
                    ) as run,
                    self.assertRaises(type(error)) as raised,
                ):
                    fuzz.run(self.root, "120", True)
                self.assertIs(raised.exception, error)
                self.assertEqual(run.call_count, 9)
                self.assertEqual(
                    list(minimized.iterdir()), [minimized / "previous.bin"]
                )
                self.assertEqual((minimized / "previous.bin").read_bytes(), b"previous")
                self.assertEqual(list(self.root.glob(".*-min-*")), [])
                for name in ("corpus", "corpus_statuses"):
                    self.assertTrue((self.root / f"{name}-min/partial.bin").is_file())

    def test_minimization_preparation_failure_preserves_previous_corpus(self):
        minimized = self.root / "corpus_accept-min"
        minimized.mkdir()
        (minimized / "previous.bin").write_bytes(b"previous")
        expected_paths = set(self.root.iterdir())
        with (
            mock.patch.object(fuzz.subprocess, "run") as run,
            mock.patch.object(
                fuzz.tempfile,
                "mkdtemp",
                side_effect=PermissionError("workspace denied"),
            ),
            self.assertRaisesRegex(PermissionError, "workspace denied"),
        ):
            fuzz.run(self.root, "120", True)
        self.assertEqual(run.call_count, 6)
        self.assertEqual((minimized / "previous.bin").read_bytes(), b"previous")
        self.assertEqual(set(self.root.iterdir()), expected_paths)

    def test_minimization_publication_failure_restores_previous_corpus(self):
        minimized = self.root / "corpus_accept-min"
        original_rename = Path.rename
        for previous, stage in (
            (True, "backup"),
            (True, "publish"),
            (False, "publish"),
        ):
            with self.subTest(previous=previous, stage=stage):
                if previous:
                    minimized.mkdir(exist_ok=True)
                    (minimized / "previous.bin").write_bytes(b"previous")
                else:
                    shutil.rmtree(minimized)
                error = PermissionError(f"{stage} denied")

                def rename(path, destination, stage=stage, error=error):
                    if (stage == "backup" and path == minimized) or (
                        stage == "publish"
                        and path.name == "new"
                        and destination == minimized
                    ):
                        raise error
                    return original_rename(path, destination)

                with (
                    mock.patch.object(fuzz.subprocess, "run") as run,
                    mock.patch.object(Path, "rename", new=rename),
                    self.assertRaisesRegex(
                        PermissionError, f"{stage} denied"
                    ) as raised,
                ):
                    fuzz.run(self.root, "120", True)
                self.assertIs(raised.exception, error)
                self.assertEqual(run.call_count, 9)
                self.assertEqual(minimized.exists(), previous)
                if previous:
                    self.assertEqual(
                        (minimized / "previous.bin").read_bytes(), b"previous"
                    )
                self.assertEqual(list(self.root.glob(".*-min-*")), [])

    def test_minimization_failed_rollback_retains_recoverable_previous_output(self):
        minimized = self.root / "corpus_accept-min"
        minimized.mkdir()
        (minimized / "previous.bin").write_bytes(b"previous")
        original_rename = Path.rename

        def rename(path, destination):
            if destination == minimized:
                raise PermissionError("publication and rollback denied")
            return original_rename(path, destination)

        with (
            mock.patch.object(fuzz.subprocess, "run") as run,
            mock.patch.object(Path, "rename", new=rename),
            self.assertRaisesRegex(PermissionError, "publication and rollback denied"),
        ):
            fuzz.run(self.root, "120", True)
        self.assertEqual(run.call_count, 9)
        workspaces = list(self.root.glob(".*-min-*"))
        self.assertEqual(len(workspaces), 1)
        self.assertEqual(
            (workspaces[0] / "previous/previous.bin").read_bytes(), b"previous"
        )

    def test_minimization_cleanup_failure_keeps_successful_output_and_propagates(self):
        minimized = self.root / "corpus_accept-min"
        minimized.mkdir()
        (minimized / "previous.bin").write_bytes(b"previous")
        original_rmtree = shutil.rmtree

        def execute(args, **_kwargs):
            if "-merge=1" in args:
                (Path(args[2]) / "fresh.bin").write_bytes(b"fresh")

        def cleanup(path, *args, **kwargs):
            if Path(path).name.startswith(".corpus_accept-min-"):
                raise PermissionError("workspace cleanup denied")
            return original_rmtree(path, *args, **kwargs)

        with (
            mock.patch.object(fuzz.subprocess, "run", side_effect=execute) as run,
            mock.patch.object(fuzz.shutil, "rmtree", side_effect=cleanup),
            self.assertRaisesRegex(PermissionError, "workspace cleanup denied"),
        ):
            fuzz.run(self.root, "120", True)
        self.assertEqual(run.call_count, 9)
        self.assertEqual((minimized / "fresh.bin").read_bytes(), b"fresh")
        self.assertEqual(list(minimized.iterdir()), [minimized / "fresh.bin"])
        workspaces = list(self.root.glob(".*-min-*"))
        self.assertEqual(len(workspaces), 1)
        self.assertEqual(
            (workspaces[0] / "previous/previous.bin").read_bytes(), b"previous"
        )

    def test_regression_duration_and_no_merge(self):
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "120")
        self.assertEqual(len(run.call_args_list), 6)
        self.assertEqual(
            sum("-max_total_time=120" in call.args[0] for call in run.call_args_list), 3
        )

    def test_regression_routing_uses_longest_registered_name(self):
        names = ("header", "header-list", "header-list-long")
        for name in names:
            (self.root / f"fuzz_{name}.c").touch()
            (self.root / f"fuzz_{name}").touch()
            (self.root / f"corpus_{name}").mkdir()
        expected = {
            "header-boundary.bin": "header",
            "header-list-boundary.bin": "header-list",
            "header-list-long-boundary.bin": "header-list-long",
            "header-list-long-request-header-boundary.bin": "header-list-long",
            "header-list-other-multiple-dashes.bin": "header-list",
            "header-other-multiple-dashes.bin": "header",
            "snapshot-record-length-bound-exact.bin": "snapshot",
        }
        for fixture in expected:
            (self.root / "regressions" / fixture).touch()
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "120")
        calls = [call.args[0] for call in run.call_args_list]
        replay_count = len(expected) + 3
        self.assertEqual(len(calls), replay_count + 6)
        replayed = {
            Path(args[1]).name: Path(args[0]).name for args in calls[:replay_count]
        }
        for fixture, name in expected.items():
            with self.subTest(fixture=fixture):
                self.assertEqual(replayed[fixture], f"fuzz_{name}")
        self.assertTrue(
            all("-max_total_time=120" in args for args in calls[replay_count:])
        )

    def test_invalid_regression_names_fail_before_any_execution(self):
        for name in ("header", "header-list", "header-list-long"):
            (self.root / f"fuzz_{name}.c").touch()
            (self.root / f"fuzz_{name}").touch()
            (self.root / f"corpus_{name}").mkdir()
        for filename in (
            "unknown-boundary.bin",
            "zzz-unknown-boundary.bin",
            "header.bin",
            "header-list.bin",
            "header-list-long.bin",
            "headerboundary.bin",
            "headerly-boundary.bin",
            "snapshot.bin",
            "snapshotboundary.bin",
            "snapshot-.bin",
            "header-list-.bin",
            "header-list-long-.bin",
        ):
            with self.subTest(filename=filename):
                fixture = self.root / "regressions" / filename
                fixture.touch()
                try:
                    with (
                        mock.patch.object(fuzz.subprocess, "run") as run,
                        self.assertRaisesRegex(ValueError, "regression has no target"),
                    ):
                        fuzz.run(self.root, "120")
                    run.assert_not_called()
                finally:
                    fixture.unlink()

    def test_duration_boundaries_and_errors(self):
        for value in ("1", "3600", "86400", "00001"):
            self.assertEqual(fuzz.duration(value), value)
        for value in (
            "",
            "0",
            "86401",
            "999999999999999999999999",
            "-1",
            "1.5",
            "1\nPATH=x",
            "1\n",
            "１",
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                fuzz.duration(value)

    def test_missing_binary_corpus_unknown_regression_empty_targets(self):
        binary = self.root / "fuzz_accept"
        binary.unlink()
        with self.assertRaisesRegex(ValueError, "missing fuzz binary or corpus"):
            fuzz.targets(self.root)
        binary.touch()
        (self.root / "corpus_accept").rmdir()
        with self.assertRaisesRegex(ValueError, "missing fuzz binary or corpus"):
            fuzz.targets(self.root)
        (self.root / "corpus_accept").mkdir()
        (self.root / "regressions/unknown-crash.bin").touch()
        with (
            self.assertRaisesRegex(ValueError, "regression has no target"),
            mock.patch.object(fuzz.subprocess, "run") as run,
        ):
            fuzz.run(self.root, "120")
        run.assert_not_called()
        for source in self.root.glob("fuzz_*.c"):
            source.unlink()
        with self.assertRaisesRegex(ValueError, "no fuzz targets"):
            fuzz.targets(self.root)

    def test_main_cli_and_replay_all_before_failing(self):
        with (
            mock.patch.object(fuzz, "__file__", str(self.root / "run.py")),
            mock.patch.object(sys, "argv", ["run.py", "120", "--merge"]),
            mock.patch.object(fuzz.subprocess, "run") as run,
        ):
            fuzz.main()
            self.assertEqual(len(run.call_args_list), 9)
        with mock.patch.object(
            fuzz.subprocess,
            "run",
            side_effect=[
                subprocess.CalledProcessError(7, "first"),
                None,
                None,
                None,
                None,
                None,
            ],
        ) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                fuzz.run(self.root, "120")
            self.assertEqual(run.call_count, 6)
        with (
            mock.patch.object(fuzz, "__file__", str(self.root / "run.py")),
            mock.patch.object(sys, "argv", ["run.py", "120"]),
            self.assertRaises(SystemExit) as exit_,
        ):
            fuzz.main()
        self.assertEqual(exit_.exception.code, 1)
        with (
            mock.patch.object(sys, "argv", ["run.py", "0"]),
            self.assertRaises(SystemExit) as exit_,
        ):
            fuzz.main()
        self.assertEqual(exit_.exception.code, 2)

    def test_all_campaigns_attempted_after_crash(self):
        with (
            mock.patch.object(
                fuzz.subprocess,
                "run",
                side_effect=[
                    None,
                    None,
                    None,
                    subprocess.CalledProcessError(7, "first-campaign"),
                    None,
                    None,
                ],
            ) as run,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            fuzz.run(self.root, "120")
        self.assertEqual(run.call_count, 6)

    def test_cli_entry(self):
        with (
            mock.patch.object(sys, "argv", ["run.py", "0"]),
            self.assertRaises(SystemExit) as exit_,
        ):
            runpy.run_path(str(Path(fuzz.__file__)), run_name="__main__")
        self.assertEqual(exit_.exception.code, 2)

    def test_validation_installs_bounded_asan_probe_toolchain(self):
        repo = Path(__file__).resolve().parents[2]
        workflow = yaml.safe_load(
            (repo / ".github/workflows/build-test.yml").read_text()
        )
        steps = workflow["jobs"]["validation"]["steps"]
        install_index = next(
            index
            for index, step in enumerate(steps)
            if step["name"] == "Install validation tools"
        )
        validate_index = next(
            index
            for index, step in enumerate(steps)
            if step["name"] == "Validate scripts and source"
        )
        self.assertLess(install_index, validate_index)
        validate = steps[validate_index]["run"]
        invocation = "python3 ci/tools/test_ci_fuzz.py"
        self.assertIn(invocation, validate)

        def assert_toolchain_packages(document):
            steps = document["jobs"]["validation"]["steps"]
            install = next(
                step["run"]
                for step in steps
                if step["name"] == "Install validation tools"
            )
            install_command = next(
                line for line in install.splitlines() if "apt-get install" in line
            )
            packages = install_command.split("-y", 1)[1].split()
            for package in ("clang", "libclang-rt-dev"):
                self.assertIn(package, packages)

        assert_toolchain_packages(workflow)
        for missing_package in ("clang", "libclang-rt-dev"):
            fixture = yaml.safe_load(yaml.safe_dump(workflow))
            install_step = next(
                step
                for step in fixture["jobs"]["validation"]["steps"]
                if step["name"] == "Install validation tools"
            )
            install_step["run"] = install_step["run"].replace(f" {missing_package}", "")
            with (
                self.subTest(missing_package=missing_package),
                self.assertRaises(AssertionError),
            ):
                assert_toolchain_packages(fixture)

    def test_workflow_duration_selection(self):
        repo = Path(__file__).resolve().parents[2]
        doc = yaml.safe_load((repo / ".github/workflows/ci-deep.yml").read_text())
        command = next(
            step["run"]
            for step in doc["jobs"]["fuzz"]["steps"]
            if step["name"] == "Select fuzz duration"
        )
        for value, expected in [
            ("1", 0),
            ("86400", 0),
            ("00001", 0),
            ("0", 1),
            ("86401", 1),
            ("", 1),
            ("9" * 26, 1),
            ("1\nPATH=x", 1),
        ]:
            output = self.root / "github-env"
            output.write_text("")
            env = dict(
                os.environ,
                EVENT_NAME="workflow_dispatch",
                FUZZ_SECONDS_INPUT=value,
                GITHUB_ENV=str(output),
            )
            result = subprocess.run(
                ["bash", "-c", command],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertEqual(
                output.read_text(), f"FUZZ_SECS={value}\n" if expected == 0 else ""
            )
            if expected:
                self.assertIn("::error::", result.stdout)
        result = subprocess.run(
            ["bash", "-c", command],
            env=dict(env, EVENT_NAME="schedule"),
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), "FUZZ_SECS=3600\n")

    def budget_pair(self):
        (self.root / "fuzz_accept.c").unlink()
        (self.root / "regressions/accept-boundary.bin").unlink()

    def test_runner_class_budget_boundaries_and_invalid_inputs(self):
        self.budget_pair()
        for fixture in (self.root / "regressions").glob("*.bin"):
            fixture.unlink()
        for runner, accepted, rejected in (
            ("github-hosted", "8160", "8161"),
            ("self-hosted", "15360", "15361"),
        ):
            for seconds in ("3600", accepted):
                with self.subTest(runner=runner, seconds=seconds):
                    fuzz.check_budget(self.root, seconds, runner)
            with (
                self.subTest(runner=runner, seconds=rejected),
                mock.patch.object(fuzz.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "total job budget"),
            ):
                fuzz.run(self.root, rejected, runner_class=runner)
            run.assert_not_called()
        for runner, seconds in (
            ("unknown", "3600"),
            ("GitHub-hosted", "3600"),
            ("", "3600"),
            ("self-hosted", "1\nPATH=x"),
        ):
            with (
                self.subTest(runner=runner, seconds=seconds),
                mock.patch.object(fuzz.subprocess, "run") as run,
                self.assertRaises((ValueError, argparse.ArgumentTypeError)),
            ):
                fuzz.run(self.root, seconds, runner_class=runner)
            run.assert_not_called()

    def test_workflow_runner_class_budget_is_forwarded_before_build(self):
        repo = Path(__file__).resolve().parents[2]
        doc = yaml.safe_load((repo / ".github/workflows/ci-deep.yml").read_text())
        steps = doc["jobs"]["fuzz"]["steps"]
        command = next(
            s["run"] for s in steps if s["name"] == "Check total fuzz job budget"
        )
        for name in (
            "Check total fuzz job budget",
            "Fuzz regression (120s/target)",
            "Fuzz each target",
        ):
            step = next(s for s in steps if s["name"] == name)
            self.assertIn('--runner-class "$RUNNER_ENVIRONMENT"', step["run"])
        fixture = self.root / "ci/fuzz"
        fixture.mkdir(parents=True)
        shutil.copyfile(repo / "ci/fuzz/run.py", fixture / "run.py")
        for name in ("snapshot", "statuses"):
            (fixture / f"fuzz_{name}.c").touch()
        for runner, seconds, expected in (
            ("github-hosted", "3600", 0),
            ("self-hosted", "3600", 0),
            ("github-hosted", "8160", 0),
            ("github-hosted", "8161", 1),
            ("self-hosted", "15360", 0),
            ("self-hosted", "15361", 1),
            ("unknown", "3600", 2),
            ("", "3600", 2),
            ("self-hosted", "1\nPATH=x", 2),
        ):
            with self.subTest(runner=runner, seconds=seconds):
                result = subprocess.run(
                    ["bash", "-c", command],
                    cwd=self.root,
                    env=dict(os.environ, FUZZ_SECS=seconds, RUNNER_ENVIRONMENT=runner),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_runner_class_budget_with_two_regression_fixtures(self):
        self.budget_pair()
        for runner, accepted, rejected in (
            ("github-hosted", "8040", "8041"),
            ("self-hosted", "15240", "15241"),
        ):
            with self.subTest(runner=runner):
                fuzz.check_budget(self.root, accepted, runner)
                with (
                    mock.patch.object(fuzz.subprocess, "run") as run,
                    self.assertRaisesRegex(ValueError, "total job budget"),
                ):
                    fuzz.run(self.root, rejected, runner_class=runner)
                run.assert_not_called()

    def test_total_budget_accepts_current_two_target_defaults(self):
        repo = Path(__file__).resolve().parents[2]
        doc = yaml.load(
            (repo / ".github/workflows/ci-deep.yml").read_text(), Loader=yaml.BaseLoader
        )
        seconds = doc["on"]["workflow_dispatch"]["inputs"]["fuzz_seconds"]["default"]
        self.assertEqual(seconds, "3600")
        self.assertEqual(int(doc["jobs"]["fuzz"]["timeout-minutes"]), 600)
        self.assertEqual(len(list((repo / "ci/fuzz").glob("fuzz_*.c"))), 2)
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.check_budget(repo / "ci/fuzz", seconds)
        run.assert_not_called()
        self.budget_pair()
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, seconds, True)
        self.assertEqual(run.call_count, 6)
        campaigns = [
            call.args[0]
            for call in run.call_args_list
            if "-max_total_time=3600" in call.args[0]
        ]
        self.assertEqual(len(campaigns), 2)

    def test_total_budget_boundary_and_excess_before_any_execution(self):
        self.budget_pair()
        # 3600 setup + 2*(120 regression + 2*60 grace + 600 merge)
        # + 2 passes*2 fixtures*60 replay leaves 30480s for discovery.
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "15240", True, "self-hosted")
        self.assertEqual(run.call_count, 6)
        self.assertEqual(
            sum("-max_total_time=15240" in call.args[0] for call in run.call_args_list),
            2,
        )
        for seconds in ("15241", "86400"):
            with (
                self.subTest(seconds=seconds),
                mock.patch.object(fuzz.subprocess, "run") as run,
                self.assertRaisesRegex(
                    ValueError, "total job budget.*2 targets.*15240"
                ),
            ):
                fuzz.run(self.root, seconds, True, "self-hosted")
            run.assert_not_called()

    def test_total_budget_added_discovered_target_changes_admission(self):
        self.budget_pair()
        with mock.patch.object(fuzz.subprocess, "run"):
            fuzz.run(self.root, "15240", True, "self-hosted")
        (self.root / "fuzz_accept.c").touch()
        with (
            mock.patch.object(fuzz.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "total job budget.*3 targets.*9880"),
        ):
            fuzz.run(self.root, "15240", True, "self-hosted")
        run.assert_not_called()
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "9880", True, "self-hosted")
        self.assertEqual(run.call_count, 8)
        self.assertEqual(
            sum("-max_total_time=9880" in call.args[0] for call in run.call_args_list),
            3,
        )

    def test_total_budget_counts_both_fixture_replay_passes(self):
        self.budget_pair()
        (self.root / "regressions/snapshot-extra.bin").touch()
        with (
            mock.patch.object(fuzz.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "total job budget.*15180"),
        ):
            fuzz.run(self.root, "15240", runner_class="self-hosted")
        run.assert_not_called()
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "15180", runner_class="self-hosted")
        self.assertEqual(run.call_count, 5)

    def test_total_budget_check_cli_without_binaries_and_errors(self):
        self.budget_pair()
        for binary in self.root.glob("fuzz_*"):
            if binary.suffix != ".c":
                binary.unlink()
        for seconds, expected in (("3600", None), ("15240", None), ("15241", 1)):
            with (
                self.subTest(seconds=seconds),
                mock.patch.object(fuzz, "__file__", str(self.root / "run.py")),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "run.py",
                        seconds,
                        "--runner-class",
                        "self-hosted",
                        "--check-budget",
                    ],
                ),
                mock.patch.object(fuzz.subprocess, "run") as run,
            ):
                if expected is None:
                    fuzz.main()
                else:
                    with self.assertRaises(SystemExit) as raised:
                        fuzz.main()
                    self.assertEqual(raised.exception.code, expected)
                run.assert_not_called()
        for source in self.root.glob("fuzz_*.c"):
            source.unlink()
        with self.assertRaisesRegex(ValueError, "no fuzz targets"):
            fuzz.check_budget(self.root, "3600")

    def test_workflow_total_budget_preflight_before_build(self):
        repo = Path(__file__).resolve().parents[2]
        doc = yaml.safe_load((repo / ".github/workflows/ci-deep.yml").read_text())
        steps = doc["jobs"]["fuzz"]["steps"]
        names = [step["name"] for step in steps]
        preflight = names.index("Check total fuzz job budget")
        for phase in (
            "Build fuzz targets",
            "Fuzz regression (120s/target)",
            "Fuzz each target",
        ):
            self.assertLess(preflight, names.index(phase))
        command = steps[preflight]["run"]
        self.assertIn("--check-budget", command)
        self.assertIn('"$FUZZ_SECS"', command)
        fixture_root = self.root / "ci/fuzz"
        (fixture_root / "regressions").mkdir(parents=True)
        shutil.copyfile(repo / "ci/fuzz/run.py", fixture_root / "run.py")
        for name in ("snapshot", "statuses"):
            (fixture_root / f"fuzz_{name}.c").touch()
            (fixture_root / f"regressions/{name}-boundary.bin").touch()
        for seconds, expected in (("3600", 0), ("15240", 0), ("15241", 1)):
            result = subprocess.run(
                ["bash", "-c", command],
                cwd=self.root,
                env=dict(
                    os.environ, FUZZ_SECS=seconds, RUNNER_ENVIRONMENT="self-hosted"
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, expected, result.stderr)
            if expected:
                self.assertIn("total job budget", result.stderr)

    def test_build_discovery_flags_and_missing_compiler(self):
        repo = Path(__file__).resolve().parents[2]
        build = self.root / "build.sh"
        shutil.copyfile(repo / "ci/fuzz/build.sh", build)
        nginx = self.root / "nginx"
        (nginx / "objs").mkdir(parents=True)
        (nginx / "objs/ngx_auto_config.h").touch()
        compiler = self.root / "compiler"
        log = self.root / "compiler.log"
        compiler.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$COMPILER_LOG"\n')
        compiler.chmod(0o700)
        env = dict(
            os.environ, NGX_SRC=str(nginx), CC=str(compiler), COMPILER_LOG=str(log)
        )
        for name in ("CFLAGS", "LIB_FUZZING_ENGINE"):
            env.pop(name, None)
        result = subprocess.run(
            ["bash", str(build), str(self.root)],
            env=env,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = log.read_text().splitlines()
        self.assertEqual(len(commands), 3)
        for name in ("snapshot", "statuses", "accept"):
            self.assertTrue(any(f"fuzz_{name}.c" in command for command in commands))
        for command in commands:
            self.assertIn("-fsanitize=address,undefined", command)
            self.assertIn("-fno-sanitize-recover=undefined", command)
            self.assertIn("-fsanitize=fuzzer", command)
        env["CC"] = str(self.root / "absent-compiler")
        result = subprocess.run(
            ["bash", str(build), str(self.root)],
            env=env,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 127)
        self.assertIn("absent-compiler", result.stderr)

    def test_missing_tool_and_crash_fail_visibly(self):
        # Real non-executable/missing-tool failure, without running a fuzzer.
        with self.assertRaises(PermissionError):
            fuzz.run(self.root, "120")
        with (
            mock.patch.object(
                fuzz.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(77, "fuzzer"),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            fuzz.run(self.root, "120")


class FuzzMergeSanitizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.build = Path(cls.tmp.name)
        source = cls.build / "merge_probe.c"
        source.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *p, size_t n) {\n"
            "  if (n && p[0] == 'B') { volatile int *q = (int *)0; *q = 1; }\n"
            "  return 0;\n}\n"
        )
        cls.binary = cls.build / "merge_probe"
        subprocess.run(
            [
                "clang",
                "-g",
                "-O1",
                "-fsanitize=fuzzer,address",
                str(source),
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.minimized = self.root / "corpus-min"
        self.minimized.mkdir()
        (self.minimized / "previous.bin").write_bytes(b"previous")
        self.completed = []
        original_run = subprocess.run

        def execute(*args, **kwargs):
            result = original_run(
                *args, **kwargs, capture_output=True, text=True, timeout=30
            )
            self.completed.append(result)
            return result

        patcher = mock.patch.object(fuzz.subprocess, "run", side_effect=execute)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_safe_merge_ignores_preexisting_crashes(self):
        stale = self.root / "crash-unrelated"
        stale.write_bytes(b"unrelated")
        (self.corpus / "good").write_bytes(b"AA")
        fuzz.minimize(self.binary, self.corpus, self.root)
        self.assertEqual(self.completed[0].returncode, 0)
        self.assertIn(b"AA", [p.read_bytes() for p in self.minimized.iterdir()])
        self.assertFalse((self.minimized / "previous.bin").exists())
        self.assertEqual(list(self.root.glob("crash-*")), [stale])
        self.assertEqual(stale.read_bytes(), b"unrelated")
        self.assertEqual(list(self.root.glob(".*-min-*")), [])

    def test_sanitizer_merge_retains_exact_reproducer_and_previous_output(self):
        for mixed in (False, True):
            with self.subTest(mixed=mixed):
                (self.corpus / "bad").write_bytes(b"B")
                if mixed:
                    (self.corpus / "good").write_bytes(b"AA")
                previous_artifacts = set(self.root.glob("crash-*"))
                with self.assertRaisesRegex(OSError, "merge produced crash artifacts"):
                    fuzz.minimize(self.binary, self.corpus, self.root)
                self.assertEqual(self.completed[-1].returncode, 0)
                self.assertIn("ERROR: AddressSanitizer:", self.completed[-1].stderr)
                if mixed:
                    self.assertIn(
                        "MERGE-OUTER: successful in 2 attempt(s)",
                        self.completed[-1].stderr,
                    )
                artifacts = set(self.root.glob("crash-*")) - previous_artifacts
                self.assertEqual(len(artifacts), 1)
                retained = [p for d in artifacts for p in d.rglob("*") if p.is_file()]
                self.assertEqual([p.read_bytes() for p in retained], [b"B"])
                self.assertEqual(
                    list(self.minimized.iterdir()), [self.minimized / "previous.bin"]
                )
                self.assertEqual(
                    (self.minimized / "previous.bin").read_bytes(), b"previous"
                )
                self.assertEqual(list(self.root.glob(".*-min-*")), [])


if __name__ == "__main__":
    unittest.main()
