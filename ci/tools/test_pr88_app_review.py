#!/usr/bin/env python3
"""Discriminating controls for PR88 review 6005131068."""

import hashlib
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import check_ci_cadence as policy
import test_ci_fuzz
import yaml
from check_ci_graph import WorkflowLoader
from test_ci_cadence import WorkflowFixture

fuzz = test_ci_fuzz.fuzz
REPO = Path(__file__).resolve().parents[2]


class AppCadenceTests(WorkflowFixture):
    def edit(self, filename, mutate):
        path = self.root / ".github/workflows" / filename
        doc = yaml.load(path.read_text(), Loader=WorkflowLoader)
        mutate(doc)
        path.write_text(yaml.safe_dump(doc, sort_keys=False))

    def test_app116_step_shapes_and_cli_error(self):
        for malformed in ("scalar", None, 3):
            with self.subTest(malformed=malformed):
                self.edit(
                    "build-test.yml",
                    lambda d, value=malformed: d["jobs"]["runtime"].__setitem__(
                        "steps", [value]
                    ),
                )
                with (
                    mock.patch.object(policy, "ROOT", self.root),
                    mock.patch("sys.stderr"),
                ):
                    self.assertEqual(policy.main(), 2)
        self.edit(
            "build-test.yml",
            lambda d: d["jobs"]["runtime"].__setitem__(
                "steps", [{"uses": "actions/checkout@sha"}]
            ),
        )
        self.assertIsInstance(policy.check(self.root), list)

    def test_app117_comment_and_executable(self):
        def change(body):
            self.edit(
                "build-test.yml",
                lambda d: d["jobs"]["validation"]["steps"].append({"run": body}),
            )

        change("  # ci/fuzz/build.sh runs monthly\necho ordinary")
        self.assertEqual(policy.check(self.root), [])
        change("bash ci/fuzz/build.sh")
        self.assertTrue(
            any("PR-reachable fuzz/MSVC" in e for e in policy.check(self.root))
        )

    def test_app118_runtime_command_and_condition(self):
        for body, condition in [
            ("chmod +x nginx-bin/nginx", None),
            ("# python3 ci/tools/test_runtime.py", None),
            ("python3 ci/tools/test_runtime.py", "${{ false }}"),
        ]:
            with self.subTest(body=body, condition=condition):

                def mutate(doc, body=body, condition=condition):
                    step = next(
                        s
                        for s in doc["jobs"]["runtime"]["steps"]
                        if s.get("name") == "Run multi-worker runtime suite"
                    )
                    step["run"] = body
                    if condition is not None:
                        step["if"] = condition

                self.edit("build-test.yml", mutate)
                self.assertTrue(
                    any("required runtime" in e for e in policy.check(self.root))
                )

    def test_app119_asan_export_producer(self):
        original = (self.root / ".github/workflows/asan.yml").read_text()
        for key, value in [
            ("id", "renamed"),
            ("if", "${{ false }}"),
            ("run", "echo export"),
            ("continue-on-error", True),
        ]:
            with self.subTest(key=key):
                (self.root / ".github/workflows/asan.yml").write_text(original)

                def mutate(doc, key=key, value=value):
                    step = next(
                        s
                        for s in doc["jobs"]["asan"]["steps"]
                        if s.get("id") == "asan-identity"
                    )
                    step[key] = value

                self.edit("asan.yml", mutate)
                self.assertIn("lost ASan metadata export step", policy.check(self.root))

    def test_app120_equivalent_and_extra_needs(self):
        for needs, valid in [
            (["msvc"], True),
            ("msvc", True),
            ([], False),
            (["msvc", "fuzz"], False),
        ]:
            with self.subTest(needs=needs):
                self.edit(
                    "ci-deep.yml",
                    lambda d, value=needs: d["jobs"]["memcheck"].__setitem__(
                        "needs", value
                    ),
                )
                errors = policy.check(self.root)
                self.assertEqual(
                    "monthly ordering/diagnostics: memcheck" not in errors,
                    valid,
                    errors,
                )

    def test_app115_timeout_and_documentation_locations(self):
        for name in ("README.md", "ci/fuzz/README.md"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, target)
        self.edit(
            "ci-deep.yml",
            lambda d: d["jobs"]["fuzz"].__setitem__("timeout-minutes", 599),
        )
        result = subprocess.run(
            [sys.executable, str(REPO / "ci/linter/workflow_policy.py"), "docs"],
            env=dict(os.environ, WORKFLOW_POLICY_ROOT=str(self.root)),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "ci-deep.yml jobs.fuzz.timeout-minutes must be 600",
            result.stdout + result.stderr,
        )
        self.assertNotIn("README.md must state", result.stdout + result.stderr)


class AppFuzzTests(unittest.TestCase):
    setUp = test_ci_fuzz.FuzzTests.setUp

    # Inherit fixture setup only; do not collect the parent suite twice.
    def test_app113_target_name_preflight(self):
        for name in ("header parser", "headers;echo", "headers.v2"):
            with self.subTest(name=name):
                source = self.root / f"fuzz_{name}.c"
                binary = self.root / f"fuzz_{name}"
                corpus = self.root / f"corpus_{name}"
                source.touch()
                binary.touch()
                corpus.mkdir()
                if name == "headers.v2":
                    self.assertIn(name, fuzz.targets(self.root))
                else:
                    with self.assertRaisesRegex(
                        ValueError, "unsupported fuzz target name"
                    ):
                        fuzz.targets(self.root)
                source.unlink()
                binary.unlink()
                corpus.rmdir()

    def test_app113_build_name_preflight(self):
        build = self.root / "build.sh"
        shutil.copyfile(REPO / "ci/fuzz/build.sh", build)
        nginx = self.root / "nginx"
        (nginx / "objs").mkdir(parents=True)
        (nginx / "objs/ngx_auto_config.h").touch()
        compiler = self.root / "compiler"
        marker = self.root / "compiled"
        compiler.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
        compiler.chmod(0o700)
        for name, valid in [
            ("header parser", False),
            ("headers;echo", False),
            ("headers.v2", True),
        ]:
            with self.subTest(name=name):
                source = self.root / f"fuzz_{name}.c"
                source.touch()
                result = subprocess.run(
                    ["bash", str(build), str(self.root)],
                    env=dict(os.environ, NGX_SRC=str(nginx), CC=str(compiler)),
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0 if valid else 1, result.stderr)
                self.assertEqual(marker.exists(), valid)
                source.unlink()

    def test_app121_disabled_install_is_detected(self):
        fixture = self.root / "fixture"
        for name in (
            "ci/tools/test_ci_fuzz.py",
            "ci/fuzz/run.py",
            ".github/workflows/build-test.yml",
        ):
            target = fixture / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, target)
        workflow = fixture / ".github/workflows/build-test.yml"
        workflow.write_text(
            workflow.read_text().replace(
                "- name: Install validation tools",
                "- name: Install validation tools\n        if: ${{ false }}",
            )
        )
        result = subprocess.run(
            [
                sys.executable,
                str(fixture / "ci/tools/test_ci_fuzz.py"),
                "FuzzTests.test_validation_installs_bounded_asan_probe_toolchain",
            ],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(
            result.returncode, 0, "disabled install escaped the policy test"
        )
        self.assertIn(b"toolchain install must be unconditional", result.stderr)

    def test_app114_failed_replay_retained_success_clean(self):
        fixture = self.root / "regressions/snapshot-boundary.bin"
        fixture.write_bytes(b"failed replay bytes")
        with mock.patch.object(fuzz.subprocess, "run"):
            fuzz.run(self.root, "1")
        self.assertEqual(list(self.root.glob("crash-*")), [])

        def execute(args, **kwargs):
            if str(fixture) in args:
                raise subprocess.CalledProcessError(7, args)

        with (
            mock.patch.object(fuzz.subprocess, "run", side_effect=execute),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            fuzz.run(self.root, "1")
        artifacts = list(self.root.glob("crash-fuzz_snapshot-*"))
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].read_bytes(), fixture.read_bytes())

    def test_app122_merge_uses_private_tested_bytes(self):
        corpus = self.root / "corpus"
        seed = corpus / "seed"
        for changed in (False, True):
            with self.subTest(changed=changed):
                seed.write_bytes(b"AA")

                def merge(args, changed=changed, **kwargs):
                    tested = next(p for p in Path(args[3]).rglob("*") if p.is_file())
                    before = tested.read_bytes()
                    if changed:
                        seed.write_bytes(b"BB")
                    copied = tested.read_bytes()
                    output = (
                        Path(args[2])
                        / hashlib.sha1(copied, usedforsecurity=False).hexdigest()
                    )
                    output.write_bytes(copied)
                    control = Path(
                        next(
                            a.split("=", 1)[1]
                            for a in args
                            if a.startswith("-merge_control_file=")
                        )
                    )
                    control.write_text(
                        f"1\n0\n{tested}\nSTARTED 0 {len(before)}\nFT 0 1\n"
                    )

                with mock.patch.object(fuzz, "run_merge", side_effect=merge):
                    fuzz.minimize(self.root / "fuzz_snapshot", corpus, self.root)
                published = list((self.root / "minimized/corpus").iterdir())
                self.assertEqual([p.read_bytes() for p in published], [b"AA"])


if __name__ == "__main__":
    unittest.main()
