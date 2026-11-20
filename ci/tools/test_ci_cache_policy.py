#!/usr/bin/env python3
"""Regression controls for the executable-cache and ASan artifact trust edges."""

import os
import pathlib
import subprocess
import tempfile
import unittest

import test_ci_executable_cache
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]


class CachePolicy(unittest.TestCase):
    def test_compiler_cache_trust(self):
        action = yaml.safe_load(
            (ROOT / ".github/actions/build-cache/action.yml").read_text()
        )
        steps = action["runs"]["steps"]
        caches = [step for step in steps if "actions/cache@" in step.get("uses", "")]
        self.assertEqual(len(caches), 3, "compiler objects, source and exact trees")
        compiler = next(step for step in caches if "ccache" in step["name"])
        self.assertEqual(
            compiler["if"],
            "github.event_name != 'pull_request' && "
            "github.event_name != 'pull_request_target'",
            "PR compiler objects must never restore/save across runs",
        )
        key = compiler["with"]["key"]
        for dimension in ("runner.os", "runner.arch", "outputs.scope", "outputs.build"):
            self.assertIn(dimension, key)
        self.assertEqual(compiler["with"]["path"], "${{ steps.identity.outputs.path }}")
        prefixes = compiler["with"]["restore-keys"].splitlines()
        self.assertEqual(len(prefixes), 2)
        for prefix in prefixes:
            for dimension in (
                "outputs.scope",
                "inputs.mode",
                "inputs.flavor",
                "inputs.nginx-version",
            ):
                self.assertIn(dimension, prefix)
        self.assertIn("outputs.build", prefixes[0])
        identity = next(step for step in steps if step.get("id") == "identity")
        self.assertIn("CI_BUILD_CACHE_PREPARE_ONLY=1", identity["run"])

    def test_executable_cache_service_boundary(self):
        action = yaml.safe_load(
            (ROOT / ".github/actions/build-cache/action.yml").read_text()
        )
        steps = action["runs"]["steps"]
        prepare = next(s for s in steps if s.get("id") == "identity")
        restore = next(s for s in steps if s.get("id") == "executable")
        self.assertLess(steps.index(prepare), steps.index(restore))
        self.assertIn("CI_BUILD_CACHE_PREPARE_ONLY=1", prepare["run"])
        self.assertEqual(
            restore["if"],
            "steps.identity.outputs.eligible == 'true' && "
            "github.ref == 'refs/heads/main' && "
            "(github.event_name == 'push' || github.event_name == 'schedule' || "
            "github.event_name == 'workflow_dispatch')",
            "executable restore/save requires eligibility and the trusted event/ref allowlist",
        )
        self.assertTrue(restore["uses"].startswith("actions/cache@"))
        self.assertNotIn(
            "restore-keys", restore["with"], "no executable prefix fallback"
        )
        self.assertEqual(
            restore["with"]["key"],
            "executable-v3-${{ runner.os }}-${{ runner.arch }}-"
            "${{ steps.identity.outputs.scope }}-${{ steps.identity.outputs.build }}",
        )
        self.assertEqual(restore["with"]["path"], "${{ steps.identity.outputs.tree }}")
        self.assertEqual(
            action["outputs"]["exact-hit"]["value"],
            "${{ steps.executable.outputs.cache-hit }}",
            "hit must come from this service restore",
        )
        self.assertEqual(
            action["outputs"]["identity"]["value"],
            "${{ steps.identity.outputs.build }}",
        )
        for file, build in (
            ("asan.yml", "Build with sanitizers"),
            ("build-test.yml", "Build server and dynamic module"),
            ("build-test.yml", "Build dynamic module"),
        ):
            workflow = yaml.safe_load((ROOT / ".github/workflows" / file).read_text())
            job = next(
                j
                for j in workflow["jobs"].values()
                if any(s.get("name") == build for s in j.get("steps", []))
            )
            builder = next(s for s in job["steps"] if s.get("name") == build)
            cache = next(s for s in job["steps"] if s.get("id") == "build-cache")
            self.assertLess(job["steps"].index(cache), job["steps"].index(builder))
            for name, output in (
                ("CI_BUILD_CACHE_HIT", "exact-hit"),
                ("CI_BUILD_CACHE_IDENTITY", "identity"),
            ):
                self.assertEqual(
                    builder["env"][name],
                    "${{ steps.build-cache.outputs." + output + " }}",
                )
            self.assertNotIn("CI_BUILD_CACHE_HIT", job.get("env", {}))
            if "CC" in builder["env"]:
                self.assertEqual(cache["env"]["CC"], builder["env"]["CC"])

    def test_asan_artifact_retention_covers_retry_window(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/asan.yml").read_text())
        upload = next(
            s
            for s in workflow["jobs"]["asan"]["steps"]
            if s.get("id") == "asan-artifact"
        )
        retention = upload["with"]["retention-days"]
        self.assertIs(type(retention), int)
        self.assertGreaterEqual(retention, 31, "cover the 30-day rerun window")

    def test_same_run_plain_asan_producer_consumer(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/asan.yml").read_text())
        producer = workflow["jobs"]["asan"]
        consumer = workflow["jobs"]["asan-reload"]
        self.assertEqual(consumer["needs"], "asan")
        self.assertEqual(
            producer["outputs"]["artifact-id"],
            "${{ steps.asan-artifact.outputs.artifact-id }}",
        )
        upload = next(s for s in producer["steps"] if s.get("id") == "asan-artifact")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertEqual(upload["with"]["path"], ".build/asan-artifact/nginx")
        download = next(
            s
            for s in consumer["steps"]
            if "actions/download-artifact@" in s.get("uses", "")
        )
        self.assertEqual(
            download["with"]["artifact-ids"], "${{ needs.asan.outputs.artifact-id }}"
        )
        for key in ("name", "pattern", "run-id"):
            self.assertNotIn(key, download["with"], "download must use the same-run ID")
        verification = next(
            s
            for s in consumer["steps"]
            if "ci-build-artifact.sh import" in s.get("run", "")
        )
        for name, output in (
            ("EXPECTED_BUILD_IDENTITY", "build-identity"),
            ("EXPECTED_BINARY_SHA256", "binary-sha256"),
            ("EXPECTED_ARTIFACT_IDENTITY", "artifact-identity"),
            ("EXPECTED_ARTIFACT_SHA256", "artifact-sha256"),
        ):
            self.assertEqual(
                verification["env"][name], "${{ needs.asan.outputs." + output + " }}"
            )
        for name, output in (
            ("build-identity", "identity"),
            ("binary-sha256", "sha256"),
            ("artifact-identity", "artifact-identity"),
            ("artifact-sha256", "artifact-sha256"),
        ):
            self.assertEqual(
                producer["outputs"][name],
                "${{ steps.asan-identity.outputs." + output + " }}",
            )
        self.assertFalse(
            any("ci-build.sh nginx" in s.get("run", "") for s in consumer["steps"]),
            "reload consumer must not build the plain variant again",
        )
        runtime_index = next(
            i
            for i, s in enumerate(consumer["steps"])
            if "--nginx-binary" in s.get("run", "")
        )
        self.assertLess(consumer["steps"].index(verification), runtime_index)
        runs = [s.get("run", "") for s in producer["steps"]]
        self.assertIn('bash ci/tools/ci-build.sh nginx "$NGINX_VERSION" asan', runs)
        self.assertIn(
            'TEST_HARNESS=1 bash ci/tools/ci-build.sh nginx "$NGINX_VERSION" asan', runs
        )


class CompilerCachePreparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="compiler-cache-policy-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        tools = self.repo / "ci/tools"
        tools.mkdir(parents=True)
        # Keep the action's filesystem preparation real; stub only the build
        # identity subprocess, whose executable trust controls have their own fixture.
        (tools / "ci-build.sh").write_text(
            "set -euo pipefail\n"
            '[[ "$CI_BUILD_CACHE_PREPARE_ONLY" == 1 ]]\n'
            '[[ "$1" == "$BUILD_FLAVOR" ]]\n'
            '[[ "$2" == "$BUILD_VERSION" ]]\n'
            '[[ "$3" == "$BUILD_MODE" ]]\n'
            'printf "tree=fixture-executable-tree\\n" >> "$GITHUB_OUTPUT"\n'
            'printf "%s\\n" "${FIXTURE_IDENTITY:-expected-build-identity}"\n'
        )
        (tools / "build-identity.sh").write_text(
            (ROOT / "ci/tools/build-identity.sh").read_text()
        )
        self.runner = self.root / "runner temp"
        self.runner.mkdir()
        self.env = {
            "PATH": os.defpath,
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "BUILD_MODE": "asan",
            "BUILD_FLAVOR": "nginx",
            "BUILD_VERSION": "1.31.3",
            "RUNNER_TEMP": str(self.runner),
            "GITHUB_OUTPUT": str(self.root / "outputs"),
            "GITHUB_ENV": str(self.root / "env"),
        }
        action = yaml.safe_load(
            (ROOT / ".github/actions/build-cache/action.yml").read_text()
        )
        self.script = next(
            s["run"] for s in action["runs"]["steps"] if s.get("id") == "identity"
        )

    def prepare(self, *, success=True, **overrides):
        env = self.env | overrides
        for name in ("GITHUB_OUTPUT", "GITHUB_ENV"):
            pathlib.Path(env[name]).write_text("")
        result = subprocess.run(
            ["bash", "-c", self.script],
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        output = dict(
            line.split("=", 1)
            for line in pathlib.Path(env["GITHUB_OUTPUT"]).read_text().splitlines()
        )
        exported = pathlib.Path(env["GITHUB_ENV"]).read_text()
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(exported, f"CCACHE_DIR={output['path']}\n")
            self.assertEqual(output["tree"], "fixture-executable-tree")
            self.assertEqual(
                output["build"],
                env.get("FIXTURE_IDENTITY", "expected-build-identity"),
            )
        else:
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn("path", output)
            self.assertEqual(exported, "")
        return result, output

    def test_same_context_has_stable_service_path_and_clears_stale_disk(self):
        _, first = self.prepare()
        cache = pathlib.Path(first["path"])
        (cache / "poisoned-object").write_text("untrusted prior run")
        sibling = self.runner / "sibling"
        sibling.mkdir()
        (sibling / "sentinel").write_text("preserve sibling")
        (cache / "nested-link").symlink_to(sibling, target_is_directory=True)
        _, second = self.prepare()
        self.assertEqual(first["path"], second["path"], "cache version path changed")
        self.assertEqual(list(cache.iterdir()), [], "stale disk cache survived")
        self.assertEqual((sibling / "sentinel").read_text(), "preserve sibling")
        self.assertEqual(cache.stat().st_mode & 0o777, 0o700)

    def test_variant_and_ref_paths_are_isolated(self):
        _, first = self.prepare()
        cache = pathlib.Path(first["path"])
        sentinel = cache / "sentinel"
        sentinel.write_text("other context")
        paths = {first["path"]}
        for name, value in (
            ("GITHUB_REPOSITORY", "other/repo"),
            ("GITHUB_REF", "refs/heads/other"),
            ("BUILD_MODE", "debug"),
            ("BUILD_FLAVOR", "angie"),
            ("BUILD_VERSION", "1.31.4"),
        ):
            with self.subTest(dimension=name):
                _, other = self.prepare(**{name: value})
                self.assertNotIn(other["path"], paths)
                paths.add(other["path"])
                self.assertEqual(sentinel.read_text(), "other context")

    def test_identity_change_keeps_compatible_object_fallback_path(self):
        _, first = self.prepare()
        _, second = self.prepare(FIXTURE_IDENTITY="changed-build-identity")
        self.assertEqual(first["path"], second["path"])
        self.assertNotEqual(first["build"], second["build"])

    def test_hostile_leaf_is_rejected_without_following_or_removing_it(self):
        _, output = self.prepare()
        cache = pathlib.Path(output["path"])
        cache.rmdir()
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("outside cache")
        for target in (outside, self.root / "missing"):
            with self.subTest(target=target):
                cache.symlink_to(target, target_is_directory=True)
                result, _ = self.prepare(success=False)
                self.assertIn("unsafe compiler cache target", result.stderr)
                self.assertTrue(cache.is_symlink())
                self.assertEqual(sentinel.read_text(), "outside cache")
                cache.unlink()
        cache.write_text("caller file")
        result, _ = self.prepare(success=False)
        self.assertIn("unsafe compiler cache target", result.stderr)
        self.assertEqual(cache.read_text(), "caller file")

    def test_invalid_runner_roots_are_rejected(self):
        ancestor = self.root / "linked-parent"
        ancestor.symlink_to(self.root, target_is_directory=True)
        # Existing directories ensure control-character rejection is exercised,
        # rather than passing only because the injected path does not exist.
        injected_roots = [
            pathlib.Path(str(self.runner) + "\nINJECTED=1"),
            pathlib.Path(str(self.runner) + "\r"),
        ]
        for root in injected_roots:
            root.mkdir()
        for runner_temp in (
            "",
            "/",
            "relative",
            str(self.root / "missing"),
            str(ancestor / self.runner.name),
            str(self.runner) + "/../runner temp",
            *(str(root) for root in injected_roots),
        ):
            with self.subTest(runner_temp=runner_temp):
                result, _ = self.prepare(success=False, RUNNER_TEMP=runner_temp)
                self.assertIn("invalid RUNNER_TEMP for compiler cache", result.stderr)
        for root in [self.runner, *injected_roots]:
            self.assertEqual(list(root.iterdir()), [])


def load_tests(loader, tests, _pattern):
    tests.addTests(loader.loadTestsFromModule(test_ci_executable_cache))
    return tests


if __name__ == "__main__":
    unittest.main()
