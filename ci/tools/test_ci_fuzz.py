#!/usr/bin/env python3
"""Fuzz orchestration controls, including a bounded real ASan merge probe."""

import argparse
import importlib.util
import os
import runpy
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from itertools import groupby
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


@unittest.skipUnless(os.name == "posix", "merge process groups are POSIX")
class MergeProcessTests(unittest.TestCase):
    @staticmethod
    def worker_stopped(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        if sys.platform == "linux":
            try:
                status = Path(f"/proc/{pid}/stat").read_text()
            except FileNotFoundError:
                return True  # Reaped between kill(0) and the state read.
            # The command name may contain spaces and parentheses.
            fields = status.rpartition(")")[2].split()
            return bool(fields and fields[0] == "Z")
        return False

    @unittest.skipUnless(sys.platform == "linux", "Linux zombie state control")
    def test_worker_liveness_distinguishes_owned_zombie(self):
        with subprocess.Popen([sys.executable, "-c", "pass"]) as child:
            deadline = time.monotonic() + 5
            while (
                os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                is None
            ):
                self.assertLess(time.monotonic(), deadline, "child did not exit")
                time.sleep(0.01)
            # WNOWAIT leaves this test-owned child unreaped until context exit.
            os.kill(child.pid, 0)
            self.assertTrue(
                self.worker_stopped(child.pid), "zombie reported as running"
            )
        with self.assertRaises(ProcessLookupError):
            os.kill(child.pid, 0)

    @unittest.skipUnless(sys.platform == "linux", "Linux process state control")
    def test_worker_liveness_keeps_running_processes_live(self):
        for status in ("123 (worker (name)) S 1 2", "123 (worker) R 1 2", ""):
            with (
                self.subTest(status=status),
                mock.patch.object(os, "kill"),
                mock.patch.object(Path, "read_text", return_value=status),
            ):
                self.assertFalse(self.worker_stopped(123))
        with (
            mock.patch.object(os, "kill"),
            mock.patch.object(Path, "read_text", side_effect=FileNotFoundError),
        ):
            self.assertTrue(self.worker_stopped(123))
        with (
            mock.patch.object(sys, "platform", "darwin"),
            mock.patch.object(os, "kill"),
            mock.patch.object(Path, "read_text") as read,
        ):
            self.assertFalse(self.worker_stopped(123))
            read.assert_not_called()
        with mock.patch.object(os, "kill", side_effect=ProcessLookupError):
            self.assertTrue(self.worker_stopped(123))

    def test_merge_result_and_spawn_errors_propagate(self):
        for status in (0, 7):
            with (
                self.subTest(status=status),
                mock.patch.object(fuzz.subprocess, "Popen") as popen,
                mock.patch.object(fuzz.os, "killpg") as kill,
            ):
                process = popen.return_value.__enter__.return_value
                process.communicate.return_value = ("output", "error")
                process.returncode = status
                process.pid = 123
                if status:
                    with self.assertRaises(subprocess.CalledProcessError) as raised:
                        fuzz.run_merge(["merge"], cwd="fixture", timeout=600)
                    self.assertEqual(raised.exception.returncode, status)
                else:
                    result = fuzz.run_merge(["merge"], cwd="fixture", timeout=600)
                    self.assertEqual(
                        (result.stdout, result.stderr), ("output", "error")
                    )
                popen.assert_called_once_with(
                    ["merge"], cwd="fixture", start_new_session=True
                )
                self.assertEqual(
                    process.communicate.call_args_list,
                    [mock.call(timeout=600)] + ([mock.call()] if status else []),
                )
                self.assertEqual(
                    kill.call_args_list,
                    [mock.call(123, signal.SIGKILL)] if status else [],
                )
        with (
            mock.patch.object(
                fuzz.subprocess, "Popen", side_effect=FileNotFoundError("missing")
            ),
            self.assertRaises(FileNotFoundError),
        ):
            fuzz.run_merge(["merge"], cwd="fixture", timeout=600)

    def test_timeout_reaps_direct_child_and_kills_group_after_grace(self):
        for group_missing in (False, True):
            with (
                self.subTest(group_missing=group_missing),
                mock.patch.object(fuzz.subprocess, "Popen") as popen,
                mock.patch.object(fuzz.os, "killpg") as kill,
            ):
                process = popen.return_value.__enter__.return_value
                process.pid = 123
                expired = subprocess.TimeoutExpired("merge", 600)
                process.communicate.side_effect = [
                    expired,
                    subprocess.TimeoutExpired("merge", 5),
                    (None, None),
                ]
                if group_missing:
                    kill.side_effect = ProcessLookupError
                with self.assertRaises(subprocess.TimeoutExpired) as raised:
                    fuzz.run_merge(["merge"], cwd="fixture", timeout=600)
                self.assertIs(raised.exception, expired)
                self.assertEqual(
                    kill.call_args_list,
                    [mock.call(123, signal.SIGTERM), mock.call(123, signal.SIGKILL)],
                )
                self.assertEqual(
                    process.communicate.call_args_list,
                    [mock.call(timeout=600), mock.call(timeout=5), mock.call()],
                )

    def test_interrupted_merge_kills_group_and_reaps_before_reraising(self):
        for error in (KeyboardInterrupt(), RuntimeError("wait failed")):
            for group_missing in (False, True):
                with (
                    self.subTest(
                        error=type(error).__name__, group_missing=group_missing
                    ),
                    mock.patch.object(fuzz.subprocess, "Popen") as popen,
                    mock.patch.object(fuzz.os, "killpg") as kill,
                ):
                    process = popen.return_value.__enter__.return_value
                    process.pid = 123
                    process.communicate.side_effect = [error, (None, None)]
                    if group_missing:
                        kill.side_effect = ProcessLookupError
                    with self.assertRaises(type(error)) as raised:
                        fuzz.run_merge(["merge"], cwd="fixture", timeout=600)
                    self.assertIs(raised.exception, error)
                    kill.assert_called_once_with(123, signal.SIGKILL)
                    self.assertEqual(
                        process.communicate.call_args_list,
                        [mock.call(timeout=600), mock.call()],
                    )

    def test_nonposix_retains_direct_subprocess_timeout(self):
        with (
            mock.patch.object(fuzz.os, "name", "nt"),
            mock.patch.object(fuzz.subprocess, "run") as run,
            mock.patch.object(fuzz.subprocess, "Popen") as popen,
        ):
            result = fuzz.run_merge(["merge"], cwd="fixture", timeout=600)
            self.assertIs(result, run.return_value)
            run.assert_called_once_with(
                ["merge"], check=True, cwd="fixture", timeout=600
            )
            popen.assert_not_called()

    def test_timeout_stops_descendant_before_workspace_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus"
            corpus.mkdir()
            binary = root / "merge_probe"
            pidfile = root / "child.pid"
            # The parent reaps its worker on SIGTERM. SIGKILL of only the parent
            # (subprocess.run's timeout) leaves that real worker alive.
            binary.write_text(
                f"#!{sys.executable}\n"
                "import os, signal, subprocess, sys, time\n"
                "time.sleep(0.3)\n"
                "from pathlib import Path\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import signal; signal.pause()'])\n"
                "def stop(*_):\n"
                "    child.wait()\n"
                "    sys.exit(0)\n"
                "signal.signal(signal.SIGTERM, stop)\n"
                f"Path({str(pidfile)!r}).write_text(str(child.pid))\n"
                "signal.pause()\n"
            )
            binary.chmod(0o700)
            original_communicate = subprocess.Popen.communicate
            ready = False

            def communicate(process, *args, **kwargs):
                nonlocal ready
                if not ready:
                    deadline = time.monotonic() + 30
                    while not pidfile.is_file():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            self.fail("merge probe failed to become ready")
                        time.sleep(0.01)
                    ready = True
                return original_communicate(process, *args, **kwargs)

            original_cleanup = shutil.rmtree
            checked_workspaces = []

            def cleanup(path, *args, **kwargs):
                if Path(path).name.startswith(".corpus-"):
                    checked_workspaces.append(Path(path))
                    self.assertTrue(pidfile.is_file(), "worker never started")
                    with self.assertRaises(
                        ProcessLookupError,
                        msg="merge descendant is still alive at cleanup",
                    ):
                        os.kill(int(pidfile.read_text()), 0)
                return original_cleanup(path, *args, **kwargs)

            try:
                with (
                    mock.patch.object(fuzz, "MERGE_SECONDS", 0.1),
                    mock.patch.object(subprocess.Popen, "communicate", new=communicate),
                    mock.patch.object(fuzz.shutil, "rmtree", side_effect=cleanup),
                    self.assertRaises(subprocess.TimeoutExpired),
                ):
                    fuzz.minimize(binary, corpus, root)
                self.assertEqual(
                    len(checked_workspaces), 1, "workspace cleanup not checked"
                )
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_nonzero_merge_stops_surviving_worker_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus"
            corpus.mkdir()
            pidfile = root / "worker.pid"
            binary = root / "merge_probe"
            binary.write_text(
                f"#!{sys.executable}\n"
                "import subprocess, sys\nfrom pathlib import Path\n"
                "child=subprocess.Popen([sys.executable, '-c', "
                "'import signal; signal.pause()'])\n"
                f"Path({str(pidfile)!r}).write_text(str(child.pid))\n"
                "sys.exit(7)\n"
            )
            binary.chmod(0o700)
            original_cleanup = shutil.rmtree
            checked = []

            def cleanup(path, *args, **kwargs):
                if Path(path).name.startswith(".corpus-"):
                    checked.append(path)
                    self.assertTrue(pidfile.is_file(), "merge worker never started")
                    deadline = time.monotonic() + 2
                    while not self.worker_stopped(int(pidfile.read_text())):
                        self.assertLess(
                            time.monotonic(),
                            deadline,
                            "worker survived nonzero merge exit at cleanup",
                        )
                        time.sleep(0.01)
                return original_cleanup(path, *args, **kwargs)

            try:
                with (
                    mock.patch.object(fuzz.shutil, "rmtree", side_effect=cleanup),
                    self.assertRaises(subprocess.CalledProcessError) as raised,
                ):
                    fuzz.minimize(binary, corpus, root)
                self.assertEqual(raised.exception.returncode, 7)
                self.assertEqual(len(checked), 1)
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


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
        patcher = mock.patch.object(
            fuzz,
            "run_merge",
            side_effect=lambda args, **kwargs: fuzz.subprocess.run(
                args, check=True, **kwargs
            ),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_standalone_timeout_matches_admission(self):
        repo = Path(__file__).resolve().parents[2]
        doc = yaml.safe_load((repo / ".github/workflows/fuzzing.yml").read_text())
        self.assertEqual(
            doc["jobs"]["fuzz-regression"]["timeout-minutes"] * 60,
            fuzz.RUNNER_BUDGETS["github-hosted"],
        )

    def test_minimization_rejects_symlinked_root(self):
        (self.root / "corpus/input.bin").write_bytes(b"keep")
        (self.root / "minimized").symlink_to(self.root, target_is_directory=True)
        with (
            mock.patch.object(fuzz, "run_merge") as merge,
            self.assertRaisesRegex(OSError, "symlink"),
        ):
            fuzz.minimize(self.root / "fuzz_snapshot", self.root / "corpus", self.root)
        merge.assert_not_called()
        self.assertEqual((self.root / "corpus/input.bin").read_bytes(), b"keep")

    def test_minimization_rejects_unprocessed_inputs(self):
        corpus = self.root / "corpus"
        (corpus / "input.bin").write_bytes(b"input")
        previous = self.root / "minimized/corpus"
        previous.mkdir(parents=True)
        (previous / "keep.bin").write_bytes(b"keep")
        for records in (
            None,
            "",
            "1\n0\ninput.bin\n",
            "2\n0\ninput.bin\nother.bin\nSTARTED 0 5\n",
        ):
            with self.subTest(records=records):

                def merge(args, records=records, **kwargs):
                    if records is not None:
                        control = Path(
                            next(
                                a.split("=", 1)[1]
                                for a in args
                                if a.startswith("-merge_control_file=")
                            )
                        )
                        control.write_text(records)

                with (
                    mock.patch.object(fuzz, "run_merge", side_effect=merge),
                    self.assertRaises(OSError),
                ):
                    fuzz.minimize(self.root / "fuzz_snapshot", corpus, self.root)
                self.assertEqual((previous / "keep.bin").read_bytes(), b"keep")

        # No new features is valid after every input actually ran.
        def complete(args, **kwargs):
            control = Path(
                next(
                    a.split("=", 1)[1]
                    for a in args
                    if a.startswith("-merge_control_file=")
                )
            )
            control.write_text(
                f"1\n0\n{Path(args[3]) / 'input.bin'}\nSTARTED 0 5\nFT 0\n"
            )

        with mock.patch.object(fuzz, "run_merge", side_effect=complete):
            fuzz.minimize(self.root / "fuzz_snapshot", corpus, self.root)
        self.assertEqual(list(previous.iterdir()), [])

    def test_directory_build_rejects_source_collision_before_compiler(self):
        repo = Path(__file__).resolve().parents[2]
        build = self.root / "build.sh"
        shutil.copyfile(repo / "ci/fuzz/build.sh", build)
        nginx = self.root / "nginx"
        (nginx / "objs").mkdir(parents=True)
        (nginx / "objs/ngx_auto_config.h").touch()
        compiler = self.root / "compiler"
        marker = self.root / "compiled"
        compiler.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
        compiler.chmod(0o700)
        source = self.root / "fuzz_accept.c"
        source.write_bytes(b"preserved source")
        for alias in (False, True):
            with self.subTest(alias=alias):
                if alias:
                    (self.root / "fuzz_accept").unlink()
                    (self.root / "fuzz_accept").symlink_to(source)
                else:
                    (self.root / "fuzz_accept.c.c").touch()
                result = subprocess.run(
                    ["bash", str(build), str(self.root)],
                    env=dict(os.environ, NGX_SRC=str(nginx), CC=str(compiler)),
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(b"collides with source", result.stderr)
                self.assertFalse(
                    marker.exists(), "compiler ran before output validation"
                )
                self.assertEqual(source.read_bytes(), b"preserved source")
                if not alias:
                    (self.root / "fuzz_accept.c.c").unlink()
                else:
                    (self.root / "fuzz_accept").unlink()

    def test_monthly_build_receives_exact_cache_identity(self):
        repo = Path(__file__).resolve().parents[2]
        doc = yaml.safe_load((repo / ".github/workflows/ci-deep.yml").read_text())
        steps = doc["jobs"]["fuzz"]["steps"]
        cache = next(
            s for s in steps if s.get("uses") == "./.github/actions/build-cache"
        )
        configure = next(s for s in steps if s.get("name") == "Configure nginx tree")
        self.assertEqual(
            configure.get("env"),
            {
                "CI_BUILD_CACHE_HIT": "${{ steps."
                + cache["id"]
                + ".outputs.exact-hit }}",
                "CI_BUILD_CACHE_IDENTITY": "${{ steps."
                + cache["id"]
                + ".outputs.identity }}",
            },
        )

    def test_regression_budget_does_not_double_charge_discovery(self):
        # 18 targets and 10 fixtures admit a 60s discovery pass (21000s),
        # even though charging regression as discovery again needs 22080s.
        for path in self.root.glob("fuzz_*.c"):
            path.unlink()
        for path in (self.root / "regressions").glob("*.bin"):
            path.unlink()
        for index in range(18):
            (self.root / f"fuzz_scale{index}.c").touch()
            (self.root / f"fuzz_scale{index}").touch()
            (self.root / f"corpus_scale{index}").mkdir()
        for index in range(10):
            (self.root / f"regressions/scale0-{index}.bin").touch()
        fuzz.check_budget(self.root, "60")
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "120")
        self.assertEqual(run.call_count, 28)
        # The regression pass still rejects a pass that cannot fit by itself.
        for index in range(18, 100):
            (self.root / f"fuzz_scale{index}.c").touch()
        with (
            mock.patch.object(fuzz.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "total job budget"),
        ):
            fuzz.run(self.root, "120")
        run.assert_not_called()

    def test_campaign_deadline_and_timeout_continues_later_targets(self):
        expired = subprocess.TimeoutExpired("campaign", 180)

        def execute(args, **kwargs):
            if "-max_total_time=120" in args:
                self.assertEqual(kwargs.get("timeout"), 180)
                if Path(args[0]).name == "fuzz_accept":
                    raise expired

        with (
            mock.patch.object(fuzz.subprocess, "run", side_effect=execute) as run,
            self.assertRaises(subprocess.TimeoutExpired) as raised,
        ):
            fuzz.run(self.root, "120", True)
        self.assertIs(raised.exception, expired)
        self.assertEqual(Path(run.call_args.args[0][0]).name, "fuzz_statuses")
        self.assertEqual(run.call_count, 8)  # failed campaign is not minimized

    def test_fuzz_ignore_policy_excludes_local_checkout_state(self):
        repo = Path(__file__).resolve().parents[2]
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("GIT_")
        }
        with tempfile.TemporaryDirectory() as directory:
            hostile = Path(directory)
            subprocess.run(
                ["git", "init", "-q", "--template=", directory],
                check=True,
                env=environment,
            )
            shutil.copyfile(repo / ".gitignore", hostile / ".gitignore")
            (hostile / ".git/info").mkdir(exist_ok=True)
            (hostile / ".git/info/exclude").write_text("ci/fuzz/corpus_headers/\n")
            # Prove the host checkout would wrongly ignore a curated seed.
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.excludesFile=/dev/null",
                    "check-ignore",
                    "--no-index",
                    "-q",
                    "ci/fuzz/corpus_headers/seed.bin",
                ],
                cwd=hostile,
                env=environment,
                check=False,
            )
            self.assertEqual(result.returncode, 0)
            # Use that checkout's policy; its local exclude must not propagate
            # into the independent policy-check repository.
            with mock.patch.object(
                sys.modules[__name__],
                "__file__",
                str(hostile / "ci/tools/test_ci_fuzz.py"),
            ):
                self.test_dynamic_fuzz_outputs_ignored_and_sources_addable()

    def test_dynamic_fuzz_outputs_ignored_and_sources_addable(self):
        repo = Path(__file__).resolve().parents[2]
        paths = {
            "ci/fuzz/fuzz_headers": True,
            "ci/fuzz/fuzz_headers.v2": True,
            "ci/fuzz/fuzz_headers.v2.c": False,
            "ci/fuzz/fuzz_common.h": False,
            "ci/fuzz/fuzz_headers.v2.h": False,
            "ci/fuzz/fuzz_headers.v2.dict": False,
            "ci/fuzz/corpus_headers/0123456789abcdef": True,
            "ci/fuzz/corpus_headers/seed.bin": False,
            "ci/fuzz/fuzz_headers.c": False,
            "ci/fuzz/fuzz_headers.dict": False,
            "ci/fuzz/corpus_statuses/typical": False,
            "ci/fuzz/corpus_statuses/0123456789abcdef": True,
        }
        # Check tracked policy in a new repository with no local excludes or
        # inherited repository environment; the active checkout is read-only.
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("GIT_")
        }
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            shutil.copyfile(repo / ".gitignore", fixture / ".gitignore")
            subprocess.run(
                ["git", "init", "-q", "--template=", directory],
                check=True,
                env=environment,
            )
            for path, ignored in paths.items():
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
                        cwd=fixture,
                        check=False,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, 0 if ignored else 1)

    def test_documented_budget_command_matches_workflow(self):
        repo = Path(__file__).resolve().parents[2]
        command = 'python3 ci/fuzz/run.py "$FUZZ_SECS" --runner-class "$RUNNER_ENVIRONMENT" --check-budget'
        documented = (repo / "ci/fuzz/README.md").read_text(encoding="utf-8")
        self.assertIn(f"`{command}`", " ".join(documented.split()))

    def test_replay_and_merge_timeout_continues_later_targets(self):
        for phase in ("replay", "merge"):
            with self.subTest(phase=phase):
                error = subprocess.TimeoutExpired(
                    phase, 60 if phase == "replay" else 600
                )

                def execute(args, phase=phase, error=error, **kwargs):
                    if "-merge=1" in args:
                        self.assertEqual(kwargs.get("timeout"), 600)
                        if phase == "merge" and Path(args[0]).name == "fuzz_accept":
                            raise error
                    elif args[-1].endswith(".bin") and phase == "replay":
                        self.assertEqual(kwargs.get("timeout"), 60)
                        if Path(args[0]).name == "fuzz_accept":
                            raise error

                with (
                    mock.patch.object(
                        fuzz.subprocess, "run", side_effect=execute
                    ) as run,
                    self.assertRaises(subprocess.TimeoutExpired) as raised,
                ):
                    fuzz.run(self.root, "120", True)
                self.assertIs(raised.exception, error)
                self.assertEqual(run.call_count, 3 if phase == "replay" else 9)
                self.assertEqual(Path(run.call_args.args[0][0]).name, "fuzz_statuses")
                self.assertEqual(list(self.root.glob(".corpus*-*")), [])

    def test_timeout_cli_reports_failure(self):
        with (
            mock.patch.object(
                fuzz, "run", side_effect=subprocess.TimeoutExpired("replay", 60)
            ),
            mock.patch.object(sys, "argv", ["run.py", "120"]),
            self.assertRaises(SystemExit) as raised,
        ):
            fuzz.main()
        self.assertEqual(raised.exception.code, 1)

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
            minimized = self.root / "minimized" / name
            (minimized / "nested").mkdir(parents=True)
            (minimized / "nested/stale.bin").write_bytes(b"stale")
        expected_paths = set(self.root.iterdir())
        destinations = []
        for payload in (b"first", b"second"):

            def execute(args, *, check, cwd, payload=payload, **_kwargs):
                self.assertTrue(check)
                self.assertEqual(cwd, self.root)
                if "-merge=1" in args:
                    pending, corpus = map(Path, args[2:4])
                    self.assertEqual(list(pending.iterdir()), [])
                    self.assertEqual(pending.parent.parent, self.root)
                    self.assertNotEqual(pending, self.root / "minimized" / corpus.name)
                    self.assertEqual((corpus / "input.bin").read_bytes(), b"input")
                    destinations.append(pending)
                    (pending / "fresh.bin").write_bytes(payload)
                    control = Path(
                        next(
                            a.split("=", 1)[1]
                            for a in args
                            if a.startswith("-merge_control_file=")
                        )
                    )
                    control.write_text(
                        f"1\n0\n{corpus / 'input.bin'}\nSTARTED 0 5\nFT 0\n"
                    )

            with mock.patch.object(fuzz.subprocess, "run", side_effect=execute) as run:
                fuzz.run(self.root, "120", True)
            self.assertEqual(run.call_count, 9)
            for name in corpora:
                minimized = self.root / "minimized" / name
                self.assertEqual(list(minimized.iterdir()), [minimized / "fresh.bin"])
                self.assertEqual((minimized / "fresh.bin").read_bytes(), payload)
            self.assertEqual(set(self.root.iterdir()), expected_paths)
        self.assertEqual(len(set(destinations)), 6)

    def test_minimization_can_publish_empty_output_without_previous_corpus(self):
        expected_paths = set(self.root.iterdir())
        with mock.patch.object(fuzz.subprocess, "run"):
            fuzz.run(self.root, "120", True)
        for name in ("corpus", "corpus_accept", "corpus_statuses"):
            minimized = self.root / "minimized" / name
            expected_paths.add(self.root / "minimized")
            self.assertTrue(minimized.is_dir())
            self.assertEqual(list(minimized.iterdir()), [])
        self.assertEqual(set(self.root.iterdir()), expected_paths)

    def test_minimization_failure_preserves_previous_corpus_and_continues(self):
        minimized = self.root / "minimized/corpus_accept"
        minimized.mkdir(parents=True)
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
                self.assertEqual(list(self.root.glob(".corpus*-*")), [])
                for name in ("corpus", "corpus_statuses"):
                    self.assertTrue(
                        (self.root / "minimized" / name / "partial.bin").is_file()
                    )

    def test_minimization_preparation_failure_preserves_previous_corpus(self):
        minimized = self.root / "minimized/corpus_accept"
        minimized.mkdir(parents=True)
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
        minimized = self.root / "minimized/corpus_accept"
        original_rename = Path.rename
        for previous, stage in (
            (True, "backup"),
            (True, "publish"),
            (False, "publish"),
        ):
            with self.subTest(previous=previous, stage=stage):
                if previous:
                    minimized.mkdir(parents=True, exist_ok=True)
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
                self.assertEqual(list(self.root.glob(".corpus*-*")), [])

    def test_minimization_failed_rollback_retains_recoverable_previous_output(self):
        minimized = self.root / "minimized/corpus_accept"
        minimized.mkdir(parents=True)
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
        workspaces = list(self.root.glob(".corpus*-*"))
        self.assertEqual(len(workspaces), 1)
        self.assertEqual(
            (workspaces[0] / "previous/previous.bin").read_bytes(), b"previous"
        )

    def test_minimization_cleanup_failure_keeps_successful_output_and_propagates(self):
        minimized = self.root / "minimized/corpus_accept"
        minimized.mkdir(parents=True)
        (minimized / "previous.bin").write_bytes(b"previous")
        original_rmtree = shutil.rmtree

        def execute(args, **_kwargs):
            if "-merge=1" in args:
                (Path(args[2]) / "fresh.bin").write_bytes(b"fresh")

        def cleanup(path, *args, **kwargs):
            if Path(path).name.startswith(".corpus_accept-"):
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
        workspaces = list(self.root.glob(".corpus*-*"))
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

    def test_regression_enumeration_errors_reject_before_campaigns(self):
        directory = self.root / "regressions"
        original = Path.iterdir

        def denied(path):
            if path == directory:
                raise PermissionError("unreadable regression directory")
            return original(path)

        for caller in ("admission", "replay"):
            with (
                self.subTest(caller=caller),
                mock.patch.object(Path, "iterdir", denied),
                mock.patch.object(fuzz.subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(PermissionError, "unreadable regression"):
                    if caller == "admission":
                        fuzz.check_budget(self.root, "120")
                    else:
                        with mock.patch.object(fuzz, "check_budget"):
                            fuzz.run(self.root, "120")
                run.assert_not_called()

        shutil.rmtree(directory)
        directory.touch()
        for caller in ("admission", "replay"):
            with (
                self.subTest(caller=caller),
                mock.patch.object(fuzz.subprocess, "run") as run,
            ):
                with self.assertRaises(NotADirectoryError):
                    if caller == "admission":
                        fuzz.check_budget(self.root, "120")
                    else:
                        with mock.patch.object(fuzz, "check_budget"):
                            fuzz.run(self.root, "120")
                run.assert_not_called()

    def test_regression_missing_empty_and_fixture_count_and_replay(self):
        directory = self.root / "regressions"
        shutil.rmtree(directory)
        for state in ("missing", "empty"):
            if state == "empty":
                directory.mkdir()
            with (
                self.subTest(state=state),
                mock.patch.object(fuzz.subprocess, "run") as run,
            ):
                fuzz.check_budget(self.root, "5160")
                fuzz.run(self.root, "120")
                self.assertEqual(run.call_count, 3)

        (directory / "snapshot-boundary.bin").touch()
        (directory / "unknown.txt").touch()
        with self.assertRaisesRegex(ValueError, "total job budget"):
            fuzz.check_budget(self.root, "5160")
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "120")
        self.assertEqual(run.call_count, 4)
        self.assertEqual(
            Path(run.call_args_list[0].args[0][1]).name, "snapshot-boundary.bin"
        )
        (directory / "unknown-boundary.bin").touch()
        with mock.patch.object(fuzz.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "regression has no target"):
                fuzz.run(self.root, "120")
            run.assert_not_called()

    def test_regression_routing_rejects_overlapping_registered_names(self):
        for name in ("header", "header-list"):
            (self.root / f"fuzz_{name}.c").touch()
            (self.root / f"fuzz_{name}").touch()
            (self.root / f"corpus_{name}").mkdir()
        (self.root / "regressions/header-list-boundary.bin").touch()
        with mock.patch.object(fuzz.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "ambiguous regression target"):
                fuzz.run(self.root, "120")
            run.assert_not_called()

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

    def test_regression_directory_fails_before_any_execution(self):
        fixture = self.root / "regressions" / "snapshot-extra.bin"
        fixture.mkdir()
        with (
            mock.patch.object(fuzz.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "regression is not a file"),
        ):
            fuzz.run(self.root, "120")
        run.assert_not_called()

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
            self.assertEqual(run.call_count, 3)
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
            install_step = next(
                step for step in steps if step["name"] == "Install validation tools"
            )
            self.assertNotIn(
                "if", install_step, "toolchain install must be unconditional"
            )
            install = install_step["run"]
            packages = []
            previous = ";"
            required_chain = False
            for line in install.replace("\\\n", " ").splitlines():
                lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
                lexer.whitespace_split = True
                for separator, words in groupby(
                    lexer, lambda word: word in {";", "&&", "||", "|", "&"}
                ):
                    if separator:
                        previous = next(words)
                        continue
                    command = list(words)
                    conditional = previous in {"||", "|", "&"} or (
                        previous == "&&" and not required_chain
                    )
                    previous = ";"
                    if command[:1] == ["sudo"]:
                        command = command[1:]
                    required_chain = (
                        not conditional
                        and len(command) >= 2
                        and command[0] in {"apt", "apt-get"}
                        and command[1] in {"install", "update"}
                    )
                    if (
                        required_chain
                        and len(command) >= 2
                        and command[0] in {"apt", "apt-get"}
                        and command[1] == "install"
                        # Only real installs count, regardless of a runner's
                        # pre-existing toolchain satisfying the later probe.
                        and all(
                            word
                            in {
                                "-y",
                                "--yes",
                                "--assume-yes",
                                "--no-install-recommends",
                                "--no-install-suggests",
                                "-q",
                                "-qq",
                            }
                            or not word.startswith("-")
                            for word in command[2:]
                        )
                    ):
                        packages.extend(
                            word for word in command[2:] if not word.startswith("-")
                        )
            for package in ("clang", "libclang-rt-dev"):
                self.assertIn(package, packages)

        split = yaml.safe_load(yaml.safe_dump(workflow))
        split_step = next(
            step
            for step in split["jobs"]["validation"]["steps"]
            if step["name"] == "Install validation tools"
        )
        for script in (
            "sudo apt-get install -y clang\nsudo apt-get install -y libclang-rt-dev\n",
            "sudo apt-get install -y clang && sudo apt-get install -y libclang-rt-dev",
            "sudo apt-get update; sudo apt install -y clang libclang-rt-dev",
            "sudo apt install --yes --no-install-recommends clang libclang-rt-dev",
            "sudo apt install -y clang libclang-rt-dev || echo failed",
        ):
            with self.subTest(script=script):
                split_step["run"] = script
                assert_toolchain_packages(split)
        for script in (
            "sudo apt-get install --simulate clang libclang-rt-dev",
            "sudo apt-get install --download-only clang libclang-rt-dev",
            "sudo apt install -s clang libclang-rt-dev",
            "sudo apt-get install -dy clang libclang-rt-dev",
            "sudo apt-get install -o APT::Get::Simulate=true clang libclang-rt-dev",
            "sudo apt-get install -y clang; false && sudo apt-get install -y libclang-rt-dev",
            "false && sudo apt-get install -y clang libclang-rt-dev",
            "sudo apt-get install -y clang || sudo apt-get install -y libclang-rt-dev",
            "sudo apt-get install -y clang ||\nsudo apt-get install -y libclang-rt-dev",
        ):
            split_step["run"] = script
            with self.subTest(fallback=script), self.assertRaises(AssertionError):
                assert_toolchain_packages(split)
        assert_toolchain_packages(workflow)
        disabled = yaml.safe_load(yaml.safe_dump(workflow))
        next(
            step
            for step in disabled["jobs"]["validation"]["steps"]
            if step["name"] == "Install validation tools"
        )["if"] = "${{ false }}"
        with self.assertRaisesRegex(AssertionError, "must be unconditional"):
            assert_toolchain_packages(disabled)
        continued = yaml.safe_load(yaml.safe_dump(workflow))
        install_step = next(
            step
            for step in continued["jobs"]["validation"]["steps"]
            if step["name"] == "Install validation tools"
        )
        install_step["run"] = (
            install_step["run"]
            .replace(" clang", " \\\n  clang", 1)
            .replace(" libclang-rt-dev", " \\\n  libclang-rt-dev", 1)
        )
        assert_toolchain_packages(continued)
        commented = yaml.safe_load(yaml.safe_dump(workflow))
        for step in commented["jobs"]["validation"]["steps"]:
            if step["name"] == "Install validation tools":
                step["run"] = "sudo apt-get install -y clang # libclang-rt-dev"
        with self.assertRaises(AssertionError):
            assert_toolchain_packages(commented)
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

    def test_validation_runs_namespace_controls(self):
        repo = Path(__file__).resolve().parents[2]
        workflow = yaml.safe_load(
            (repo / ".github/workflows/build-test.yml").read_text()
        )
        validate = next(
            step["run"]
            for step in workflow["jobs"]["validation"]["steps"]
            if step["name"] == "Validate scripts and source"
        )
        self.assertIn(
            "python3 -m unittest ci.tools.test_fuzz_namespace", validate.splitlines()
        )

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
                fuzz.run(self.root, rejected, True, runner_class=runner)
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
                    fuzz.run(self.root, rejected, True, runner_class=runner)
                run.assert_not_called()

    def test_total_budget_accepts_current_two_target_defaults(self):
        repo = Path(__file__).resolve().parents[2]
        doc = yaml.load(
            (repo / ".github/workflows/ci-deep.yml").read_text(), Loader=yaml.BaseLoader
        )
        seconds = doc["on"]["workflow_dispatch"]["inputs"]["fuzz_seconds"]["default"]
        self.assertEqual(seconds, "3600")
        self.assertEqual(int(doc["jobs"]["fuzz"]["timeout-minutes"]), 600)
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
            fuzz.run(self.root, "15240", True, runner_class="self-hosted")
        run.assert_not_called()
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "15180", True, runner_class="self-hosted")
        self.assertEqual(run.call_count, 7)

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
        (self.root / "fuzz_headers.v2.c").touch()
        result = subprocess.run(
            ["bash", str(build), str(self.root)],
            env=env,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = log.read_text().splitlines()
        self.assertEqual(len(commands), 4)
        for name in ("snapshot", "statuses", "accept", "headers.v2"):
            self.assertTrue(any(f"fuzz_{name}.c" in command for command in commands))
        for command in commands:
            self.assertIn("-fsanitize=address,undefined", command)
            self.assertIn("-fno-sanitize-recover=undefined", command)
            self.assertIn("-fsanitize=fuzzer", command)
        for suffix in ("dict", "h", "c"):
            reserved = self.root / f"fuzz_reserved.{suffix}.c"
            reserved.touch()
            result = subprocess.run(
                ["bash", str(build), str(self.root)],
                env=env,
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("reserved source extension", result.stderr)
            self.assertEqual(len(log.read_text().splitlines()), 4)
            reserved.unlink()
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
        self.minimized = self.root / "minimized/corpus"
        self.minimized.mkdir(parents=True)
        (self.minimized / "previous.bin").write_bytes(b"previous")
        self.completed = []
        original_run = fuzz.run_merge

        def execute(*args, **kwargs):
            kwargs["timeout"] = 30  # Bound this single-input sanitizer diagnostic.
            result = original_run(
                *args,
                **kwargs,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.completed.append(result)
            return result

        patcher = mock.patch.object(fuzz, "run_merge", side_effect=execute)
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
        self.assertEqual(list(self.root.glob(".corpus*-*")), [])

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
                self.assertEqual(list(self.root.glob(".corpus*-*")), [])


if __name__ == "__main__":
    unittest.main()
