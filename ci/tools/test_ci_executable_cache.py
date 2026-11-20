#!/usr/bin/env python3
"""Run the action's eligibility gate with real build scripts and fake compilation.

The cache boundary is mocked: the local service records only trees admitted by
its actual action condition. Hosted cache transport is outside this test.
"""

import ast
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
OVERRIDES = (
    "GCC_EXEC_PREFIX",
    "COMPILER_PATH",
    "LIBRARY_PATH",
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH",
    "NGX_ERROR_ABUSE_INCS",
    "NGX_ERROR_ABUSE_LIBS",
)


class ExecutableCacheEligibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="executable-cache-policy-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = pathlib.Path(cls.temp.name).resolve()
        # Reuse the maintained tiny-source/fake-make setup, ending before its
        # tests. A missing boundary fails setup rather than running that suite.
        fixture = (ROOT / "ci/tools/test-ci-build-cache.sh").read_text()
        setup, boundary, _ = fixture.partition("\nfail()")
        if not boundary:
            raise AssertionError("build-cache fixture setup boundary missing")
        setup = setup.replace(
            'repo="$(git rev-parse --show-toplevel)"',
            f"repo={shlex.quote(str(ROOT))}",
        )
        setup += '\ntrap - EXIT\nprintf "%s\\n" "$tmp"\n'
        result = subprocess.run(
            ["bash", "-c", setup],
            env={"PATH": os.defpath, "TMPDIR": str(cls.root)},
            capture_output=True,
            text=True,
            check=True,
        )
        cls.fixture = pathlib.Path(result.stdout.strip())
        cls.repo = cls.fixture / "repo"
        cls.env = {
            "PATH": f"{cls.fixture / 'bin'}:/usr/bin:/bin",
            "OPERATIONS": str(cls.fixture / "operations"),
            "FIXTURE_ARCHIVE": str(cls.fixture / "source.tar.gz"),
            "CCACHE_DIR": str(cls.fixture / "ccache"),
            "BUILD_ROOT": str(cls.repo / ".build"),
            "RUNNER_TEMP": str(cls.fixture),
            "GITHUB_OUTPUT": str(cls.fixture / "outputs"),
            "GITHUB_ENV": str(cls.fixture / "env"),
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push",
            "BUILD_MODE": "asan",
            "BUILD_FLAVOR": "nginx",
            "BUILD_VERSION": "1.31.3",
        }
        action = yaml.safe_load(
            (ROOT / ".github/actions/build-cache/action.yml").read_text()
        )
        cls.prepare = next(
            s["run"] for s in action["runs"]["steps"] if s.get("id") == "identity"
        )
        cls.cache = next(
            s for s in action["runs"]["steps"] if s.get("id") == "executable"
        )

    def run_script(self, args, env):
        result = subprocess.run(
            args, cwd=self.repo, env=env, capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def preparation(self, env):
        for name in ("GITHUB_OUTPUT", "GITHUB_ENV"):
            pathlib.Path(env[name]).write_text("")
        self.run_script(["bash", "-c", self.prepare], env)
        output = dict(
            line.split("=", 1)
            for line in pathlib.Path(env["GITHUB_OUTPUT"]).read_text().splitlines()
        )
        self.assertFalse(pathlib.Path(output["tree"]).exists(), "stale tree survived")
        return output

    def allowed(self, env, output):
        # Evaluate the expression from the action, not a second copy of its
        # allowlist. Only string equality is supported; Actions ignores case
        # for string comparisons, and absent step outputs are empty.
        context = {
            "github": types.SimpleNamespace(
                ref=env["GITHUB_REF"], event_name=env["GITHUB_EVENT_NAME"]
            ),
            "steps": types.SimpleNamespace(
                identity=types.SimpleNamespace(
                    outputs=types.SimpleNamespace(eligible=output.get("eligible", ""))
                )
            ),
        }
        expression = self.cache["if"].replace("&&", " and ").replace("||", " or ")

        def evaluate(node):
            if isinstance(node, ast.BoolOp):
                values = [evaluate(value) for value in node.values]
                if isinstance(node.op, ast.And):
                    return all(values)
                if isinstance(node.op, ast.Or):
                    return any(values)
            if (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.Eq)
            ):
                left, right = evaluate(node.left), evaluate(node.comparators[0])
                if not isinstance(left, str) or not isinstance(right, str):
                    raise AssertionError("cache equality requires strings")
                return left.lower() == right.lower()
            if isinstance(node, ast.Attribute):
                return getattr(evaluate(node.value), node.attr)
            if isinstance(node, ast.Name):
                return context[node.id]
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            raise AssertionError(f"unsupported cache condition: {ast.dump(node)}")

        return evaluate(ast.parse(expression, mode="eval").body)

    def key(self, output):
        values = {
            "runner.os": "Linux",
            "runner.arch": "X64",
            "steps.identity.outputs.scope": output["scope"],
            "steps.identity.outputs.build": output["build"],
        }
        return re.sub(
            r"\$\{\{ (.*?) \}\}",
            lambda match: values[match[1]],
            self.cache["with"]["key"],
        )

    def test_producers_and_ordinary_key_collisions(self):
        restore, save = Mock(), Mock()
        service = {}
        baseline = self.preparation(self.env)
        ordinary_key = self.key(baseline)
        cases = [(None, None, "true")]
        cases += [(name, None, "true") for name in OVERRIDES]
        cases += [
            (name, value, "false")
            for name in OVERRIDES
            for value in ("", str(self.fixture / "mutable override") + "/")
        ]
        for name, value, expected in cases:
            with self.subTest(variable=name, value=value):
                env = dict(self.env)
                if name is not None and value is not None:
                    env[name] = value
                output = self.preparation(env)
                key = self.key(output)
                admitted = self.allowed(env, output)
                restore.reset_mock()
                save.reset_mock()
                service.clear()
                if admitted:
                    restore(key)
                log = self.run_script(
                    ["bash", "ci/tools/ci-build.sh", "nginx", "1.31.3", "asan"],
                    env | {"CI_BUILD_CACHE_HIT": "false"},
                )
                self.assertIn("build-cache: rebuild", log)
                tree = pathlib.Path(output["tree"])
                self.assertTrue((tree / "objs/nginx").is_file())
                self.assertEqual(
                    (tree / ".build-identity").read_text().strip(), output["build"]
                )
                if admitted:
                    save(key, tree)
                    service[key] = (tree / "objs/nginx").read_bytes()
                self.assertEqual(
                    save.call_count,
                    int(expected == "true"),
                    "excluded producer reached executable cache save",
                )
                self.assertEqual(restore.call_count, int(expected == "true"))
                self.assertEqual(output.get("eligible"), expected)
                if expected == "true":
                    save.assert_called_once_with(key, tree)
                    restore.assert_called_once_with(key)
                    self.assertIn(ordinary_key, service)
                else:
                    # The two module overrides do not change the ordinary key;
                    # absence of a published tree must protect the next unset
                    # consumer even for this exact identity collision.
                    if name.startswith("NGX_ERROR_ABUSE_"):
                        self.assertEqual(key, ordinary_key)
                    self.assertNotIn(key, service)
                    self.assertNotIn(ordinary_key, service)
                    consumer_env = {k: v for k, v in env.items() if k not in OVERRIDES}
                    self.assertTrue(
                        all(name not in consumer_env for name in OVERRIDES),
                        "ordinary consumer retained producer overrides",
                    )
                    consumer_output = self.preparation(consumer_env)
                    self.assertEqual(self.key(consumer_output), ordinary_key)
                    if name.startswith("NGX_ERROR_ABUSE_"):
                        self.assertEqual(output["build"], consumer_output["build"])
                    hit = ordinary_key in service
                    self.assertFalse(hit, "unpublished producer yielded a service hit")
                    consumer = self.run_script(
                        ["bash", "ci/tools/ci-build.sh", "nginx", "1.31.3", "asan"],
                        consumer_env
                        | {
                            "CI_BUILD_CACHE_HIT": str(hit).lower(),
                            "CI_BUILD_CACHE_IDENTITY": consumer_output["build"],
                        },
                    )
                    self.assertIn("build-cache: rebuild", consumer)
                    self.assertNotIn("trusted exact service hit; reuse", consumer)

    def test_trust_and_service_hit_boundaries(self):
        output = self.preparation(self.env)
        self.run_script(
            ["bash", "ci/tools/ci-build.sh", "nginx", "1.31.3", "asan"], self.env
        )
        cases = (
            ("push", "refs/heads/main", "true"),
            ("schedule", "refs/heads/main", "true"),
            ("workflow_dispatch", "refs/heads/main", "true"),
            ("pull_request", "refs/pull/1/merge", "false"),
            ("pull_request_target", "refs/heads/main", "false"),
            ("workflow_run", "refs/heads/main", "false"),
            ("push", "refs/heads/feature", "false"),
            ("push", "refs/tags/main", "false"),
        )
        for event, ref, eligible in cases:
            env = self.env | {"GITHUB_EVENT_NAME": event, "GITHUB_REF": ref}
            with self.subTest(event=event, ref=ref):
                self.assertEqual(self.allowed(env, output), eligible == "true")
                for hit, identity in (
                    ("true", output["build"]),
                    ("false", output["build"]),
                    ("", output["build"]),
                    ("true", "mismatched identity"),
                ):
                    log = self.run_script(
                        ["bash", "ci/tools/ci-build.sh", "nginx", "1.31.3", "asan"],
                        env
                        | {
                            "CI_BUILD_CACHE_HIT": hit,
                            "CI_BUILD_CACHE_IDENTITY": identity,
                        },
                    )
                    reuse = (
                        eligible == "true"
                        and hit == "true"
                        and identity == output["build"]
                    )
                    self.assertEqual("trusted exact service hit; reuse" in log, reuse)
        for eligible in ("true", "True", "TRUE"):
            with self.subTest(eligible_output=eligible):
                self.assertTrue(self.allowed(self.env, output | {"eligible": eligible}))
        for eligible in ("false", "", "FALSE"):
            with self.subTest(eligible_output=eligible):
                self.assertFalse(
                    self.allowed(self.env, output | {"eligible": eligible})
                )
        self.assertFalse(self.allowed(self.env, {}))
        mixed = self.env | {
            "GITHUB_EVENT_NAME": "PuSh",
            "GITHUB_REF": "REFS/HEADS/MAIN",
        }
        self.assertTrue(self.allowed(mixed, output))


if __name__ == "__main__":
    unittest.main()
