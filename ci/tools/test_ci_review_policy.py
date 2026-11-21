"""Corpus and workflow policy regression controls."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_ci_cadence as cadence_fixture
import test_ci_fuzz as fuzz_fixture
import yaml
from check_ci_graph import WorkflowLoader

policy = cadence_fixture.policy
fuzz = fuzz_fixture.fuzz
REPO = Path(__file__).resolve().parents[2]


class FuzzRepairTests(unittest.TestCase):
    setUp = fuzz_fixture.FuzzTests.setUp

    def test_app61_nested_curated_and_generated_seeds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(REPO / ".gitignore", root / ".gitignore")
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("GIT_")
            }
            subprocess.run(
                ["git", "init", "-q", "--template=", directory], check=True, env=env
            )
            for corpus in ("corpus", "corpus_headers", "corpus_statuses"):
                for name, ignored in (
                    ("http2/frame.bin", False),
                    ("http2/0123456789abcdef", True),
                ):
                    result = subprocess.run(
                        [
                            "git",
                            "-c",
                            "core.excludesFile=/dev/null",
                            "check-ignore",
                            "--no-index",
                            "-q",
                            f"ci/fuzz/{corpus}/{name}",
                        ],
                        cwd=root,
                        env=env,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode, int(not ignored), (corpus, name)
                    )

    def merge_control(self, args, records, output=None):
        control = Path(
            next(
                arg.split("=", 1)[1]
                for arg in args
                if arg.startswith("-merge_control_file=")
            )
        )
        control.write_bytes(records)
        if output is not None:
            (
                Path(args[2])
                / hashlib.sha1(b"input", usedforsecurity=False).hexdigest()
            ).write_bytes(output)

    def test_app63_raw_bytes_and_malformed_records_continue_targets(self):
        for tail in (
            b"STARTED 0 5\nFT 0\n",
            b"\xff\n",
            b"STARTED 0 5\nFT nope\n",
            b"STARTED 0 5\nFT 0\nUNKNOWN 0\n",
            b"STARTED 0 5\nFT 1\n",
            b"STARTED 1 5\nFT 1\n",
            b"STARTED 0\nFT 0\n",
            b"STARTED 0 5\nFT 0\nFT 0\n",
            b"STARTED 0 5\nCOV 0 7\nFT 0\n",
        ):
            with self.subTest(tail=tail):
                (self.root / "corpus_accept" / os.fsdecode(b"seed-\xff")).write_bytes(
                    b"input"
                )
                calls = []

                def merge(args, calls=calls, tail=tail, **_kwargs):
                    calls.append(Path(args[0]).name)
                    if args[0].endswith("fuzz_accept"):
                        self.merge_control(
                            args,
                            b"1\n0\n"
                            + os.fsencode(self.root / "corpus_accept")
                            + b"/seed-\xff\n"
                            + tail,
                        )

                with (
                    mock.patch.object(fuzz, "run_merge", side_effect=merge),
                    mock.patch.object(fuzz.subprocess, "run"),
                ):
                    if tail == b"STARTED 0 5\nFT 0\n":
                        fuzz.run(self.root, "120", True)
                    else:
                        with self.assertRaises(OSError):
                            fuzz.run(self.root, "120", True)
                self.assertEqual(
                    calls, ["fuzz_accept", "fuzz_snapshot", "fuzz_statuses"]
                )

    def test_app64_complete_replacement_before_publication(self):
        corpus = self.root / "corpus"
        (corpus / "input").write_bytes(b"input")
        previous = self.root / "minimized/corpus"
        previous.mkdir(parents=True)
        (previous / "keep").write_bytes(b"previous")
        records = (
            b"1\n0\n"
            + os.fsencode(corpus / "input")
            + b"\nSTARTED 0 5\nFT 0 42\nCOV 0 7\n"
        )
        for output in (None, b"in", b"wrong"):
            with self.subTest(output=output):
                with (
                    mock.patch.object(
                        fuzz,
                        "run_merge",
                        side_effect=lambda args, output=output, **_kwargs: (
                            self.merge_control(args, records, output)
                        ),
                    ),
                    self.assertRaisesRegex(OSError, "replacement"),
                ):
                    fuzz.minimize(self.root / "fuzz_snapshot", corpus, self.root)
                self.assertEqual((previous / "keep").read_bytes(), b"previous")
        with mock.patch.object(
            fuzz,
            "run_merge",
            side_effect=lambda args, **_kwargs: self.merge_control(
                args, records, b"input"
            ),
        ):
            fuzz.minimize(self.root / "fuzz_snapshot", corpus, self.root)
        self.assertEqual(
            (
                previous / hashlib.sha1(b"input", usedforsecurity=False).hexdigest()
            ).read_bytes(),
            b"input",
        )
        empty = records.replace(b"FT 0 42", b"FT 0")
        with mock.patch.object(
            fuzz,
            "run_merge",
            side_effect=lambda args, **_kwargs: self.merge_control(args, empty),
        ):
            fuzz.minimize(self.root / "fuzz_snapshot", corpus, self.root)
        self.assertEqual(list(previous.iterdir()), [])

    def test_app65_new_target_cannot_reassign_existing_fixture(self):
        fixture = self.root / "regressions/snapshot-record-length-bound-exact.bin"
        fixture.touch()
        with mock.patch.object(fuzz.subprocess, "run") as run:
            fuzz.run(self.root, "120")
        self.assertIn(
            mock.call(
                [str(self.root / "fuzz_snapshot"), str(fixture)],
                check=True,
                cwd=self.root,
                timeout=60,
            ),
            run.call_args_list,
        )
        (self.root / "fuzz_snapshot-record-length.c").touch()
        (self.root / "fuzz_snapshot-record-length").touch()
        (self.root / "corpus_snapshot-record-length").mkdir()
        with mock.patch.object(fuzz.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "ambiguous regression target"):
                fuzz.run(self.root, "120")
            run.assert_not_called()


class CadenceRepairTests(cadence_fixture.WorkflowFixture):
    def deep(self, mutate):
        path = self.root / ".github/workflows/ci-deep.yml"
        doc = yaml.load(path.read_text(), Loader=WorkflowLoader)
        mutate(doc)
        path.write_text(yaml.safe_dump(doc))

    def test_app68_reload_requires_artifact_guard(self):
        path = self.root / ".github/workflows/asan.yml"
        baseline = path.read_text()
        for condition in ("success()", "always()", "!cancelled()"):
            path.write_text(
                baseline.replace(
                    "${{ !cancelled() && needs.asan.outputs.artifact-id != '' }}",
                    "${{ " + condition + " }}",
                )
            )
            self.assertIn(
                "PR target cannot run on healthy PR: asan/asan-reload",
                policy.check(self.root),
            )
        path.write_text(baseline)
        self.assertEqual(policy.check(self.root), [])

    def test_app69_scheduled_budget_independent_of_manual(self):
        # Fix this boundary's inventory independently of checkout target growth.
        fuzz_root = self.root / "ci/fuzz"
        for source in fuzz_root.glob("fuzz_*.c"):
            source.unlink()
        shutil.rmtree(fuzz_root / "regressions")
        (fuzz_root / "regressions").mkdir()
        for index in range(2):
            (fuzz_root / f"fuzz_synthetic{index}.c").touch()
            (fuzz_root / f"regressions/synthetic{index}-boundary.bin").touch()
        self.deep(
            lambda doc: doc["on"]["workflow_dispatch"]["inputs"]["fuzz_seconds"].update(
                default="120"
            )
        )
        for index in range(2):
            (self.root / f"ci/fuzz/fuzz_extra{index}.c").touch()
        self.assertEqual(policy.check(self.root), [])
        (self.root / "ci/fuzz/fuzz_extra2.c").touch()
        errors = policy.check(self.root)
        self.assertTrue(
            any(
                "scheduled fuzz duration exceeds runner budget" in error
                for error in errors
            ),
            errors,
        )
        self.assertFalse(
            any("manual fuzz_seconds default exceeds" in error for error in errors),
            errors,
        )

    def test_app70_monthly_scanners_and_report_upload_required(self):
        self.assertEqual(policy.check(self.root), [])
        path = self.root / ".github/workflows/ci-deep.yml"
        baseline = path.read_text()
        for name in (
            "flawfinder",
            "clang-tidy (cert-*, security.*)",
            "semgrep",
            "Upload reports",
        ):
            path.write_text(baseline)
            self.deep(
                lambda doc, name=name: doc["jobs"]["scanners"].update(
                    steps=[
                        step
                        for step in doc["jobs"]["scanners"]["steps"]
                        if step.get("name") != name
                    ]
                )
            )
            self.assertTrue(
                any("monthly scanner" in error for error in policy.check(self.root)),
                name,
            )
        for before, after in (
            ("flawfinder --minlevel=1", "echo flawfinder --minlevel=1"),
            ("if flawfinder --minlevel=4", "if echo flawfinder --minlevel=4"),
            ('clang-tidy "$GITHUB_WORKSPACE', 'echo clang-tidy "$GITHUB_WORKSPACE'),
            ("semgrep scan", "echo semgrep scan"),
            ("tee semgrep.log || true", "tee semgrep.log"),
            (
                "${{ github.workspace }}/semgrep.log",
                "${{ github.workspace }}/wrong.log",
            ),
        ):
            path.write_text(baseline)
            self.assertIn(before, baseline)
            path.write_text(baseline.replace(before, after))
            self.assertTrue(
                any("monthly scanner" in error for error in policy.check(self.root)),
                before,
            )
        path.write_text(baseline)
        self.deep(
            lambda doc: doc["jobs"]["scanners"].update(steps=[{"run": "echo ok"}])
        )
        self.assertTrue(
            any("monthly scanner" in error for error in policy.check(self.root))
        )

    def test_monthly_scanner_early_exit_cannot_satisfy_policy(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        baseline = path.read_text()
        for name in ("flawfinder", "clang-tidy (cert-*, security.*)", "semgrep"):
            for prefix in ("exit 0\n", "if false; then\n"):
                path.write_text(baseline)

                def mutate(doc, name=name, prefix=prefix):
                    step = next(
                        step
                        for step in doc["jobs"]["scanners"]["steps"]
                        if step.get("name") == name
                    )
                    step["run"] = (
                        prefix
                        + step["run"]
                        + ("\nfi" if prefix.startswith("if") else "")
                    )

                self.deep(mutate)
                self.assertTrue(
                    any(
                        "monthly scanner" in error for error in policy.check(self.root)
                    ),
                    (name, prefix),
                )
        path.write_text(baseline)
        self.assertEqual(policy.check(self.root), [])

    def test_app62_documentation_has_both_effective_cutoffs(self):
        text = (REPO / "ci/fuzz/README.md").read_text()
        self.assertIn("GitHub-hosted jobs stop after **360 minutes**", text)
        for name in ("README.md", "ci/fuzz/README.md"):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, destination)
        command = [sys.executable, str(REPO / "ci/linter/workflow_policy.py"), "docs"]
        env = dict(os.environ, WORKFLOW_POLICY_ROOT=str(self.root))
        self.assertEqual(
            subprocess.run(
                command, env=env, capture_output=True, check=False
            ).returncode,
            0,
        )
        path = self.root / "ci/fuzz/README.md"
        path.write_text(
            text.replace(
                "GitHub-hosted jobs stop after **360 minutes**",
                "GitHub-hosted jobs stop after **600 minutes**",
            )
        )
        result = subprocess.run(command, env=env, capture_output=True, check=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"cutoff", result.stderr)


class StagedRepairTests(cadence_fixture.WorkflowFixture):
    def setUp(self):
        cadence_fixture.WorkflowFixture.setUp(self)
        for name in (
            "ci/linter/lib.sh",
            "ci/linter/run-all.sh",
            "ci/linter/lint-ci-monthly.sh",
            "ci/tools/check_ci_cadence.py",
            "ci/tools/check_ci_graph.py",
        ):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / name, target)
        self.git("init", "-q", "--template=")
        self.git("add", "-f", ".github/workflows", "ci")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "fixture",
        )

    git = cadence_fixture.StagedCadenceTests.git
    lint = cadence_fixture.StagedCadenceTests.lint

    def test_app66_relative_diff_cannot_hide_staged_workflow(self):
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        self.git("add", ".github/workflows/ci-deep.yml")
        self.git("config", "diff.relative", "true")
        result = self.lint(cwd=self.root / "ci")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"lost full fuzz duration", result.stderr)

    def test_app67_budget_import_uses_selected_root(self):
        path = self.root / ".github/workflows/ci.yml"
        path.write_text(path.read_text() + "\n# staged workflow\n")
        self.git("add", ".github/workflows/ci.yml")
        (self.root / "ci/fuzz/run.py").write_text("invalid python syntax!\n")
        result = self.lint()
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.lint(mode="all")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
