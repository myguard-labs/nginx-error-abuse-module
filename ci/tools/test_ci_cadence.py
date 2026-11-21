#!/usr/bin/env python3
"""Positive, malformed, lost-gate and fifth-leaf cadence controls."""

import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_ci_cadence as policy
import yaml
from check_ci_graph import WorkflowLoader


def fixture_environment(**overrides):
    # Git's repository-local environment (git rev-parse --local-env-vars).
    # The lint script itself must retain explicit hook indexes; only fixtures
    # clear inherited overrides, before adding their own intentional values.
    local = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_OBJECT_DIRECTORY",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_GRAFT_FILE",
        "GIT_INDEX_FILE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_REPLACE_REF_BASE",
        "GIT_PREFIX",
        "GIT_SHALLOW_FILE",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
    }
    return {
        **{
            name: value
            for name, value in os.environ.items()
            if name not in local
            and not name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
        },
        **overrides,
    }


class WorkflowFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        shutil.copytree(
            policy.ROOT / ".github/workflows", self.root / ".github/workflows"
        )

    def replace(self, name, before, after):
        path = self.root / ".github/workflows" / name
        text = path.read_text(encoding="utf-8")
        self.assertIn(before, text)
        path.write_text(text.replace(before, after), encoding="utf-8")


class CadenceTests(WorkflowFixture):
    def test_msvc_entry_points_are_only_monthly_call_and_manual(self):
        path = self.root / ".github/workflows/windows-msvc.yml"
        original = path.read_bytes()
        for events in (
            {"workflow_call": None, "workflow_dispatch": None, "push": None},
            {"workflow_call": None},
            {"workflow_dispatch": None},
        ):
            with self.subTest(events=events):
                path.write_bytes(original)
                self.update_workflow(
                    "windows-msvc.yml", lambda doc, events=events: doc.update(on=events)
                )
                self.assertIn(
                    "MSVC monthly/manual trigger contract", policy.check(self.root)
                )
        path.write_bytes(original)
        self.assertEqual(policy.check(self.root), [])

    def test_asan_output_requires_actual_upload_step(self):
        path = self.root / ".github/workflows/asan.yml"
        original = path.read_bytes()
        for field, value in (
            ("id", "renamed"),
            ("uses", "actions/download-artifact@v7"),
            ("if", False),
            ("if", "failure()"),
        ):
            with self.subTest(field=field):
                path.write_bytes(original)

                def mutate(doc, field=field, value=value):
                    step = next(
                        s
                        for s in doc["jobs"]["asan"]["steps"]
                        if s.get("id") == "asan-artifact"
                    )
                    step[field] = value

                self.update_workflow("asan.yml", mutate)
                self.assertIn("lost ASan artifact upload step", policy.check(self.root))
        path.write_bytes(original)
        self.assertEqual(policy.check(self.root), [])

    def test_asan_artifact_output_mapping_required(self):
        path = self.root / ".github/workflows/asan.yml"
        original = path.read_bytes()
        for outputs in (
            None,
            {},
            {"artifact-id": ""},
            {"artifact-id": "${{ steps.missing.outputs.artifact-id }}"},
        ):
            with self.subTest(outputs=outputs):
                path.write_bytes(original)
                self.update_workflow(
                    "asan.yml",
                    lambda doc, outputs=outputs: doc["jobs"]["asan"].update(
                        outputs=outputs
                    ),
                )
                self.assertIn(
                    "lost ASan artifact-id producer output", policy.check(self.root)
                )
        path.write_bytes(original)
        self.assertEqual(policy.check(self.root), [])

    def test_manual_fuzz_input_requires_valid_default(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_bytes()
        for inputs in (
            None,
            {},
            {"fuzz_seconds": None},
            {"fuzz_seconds": {}},
            *(
                {"fuzz_seconds": {"default": value}}
                for value in ("", "0", "86401", "999999", "1\nPATH=x", True)
            ),
        ):
            with self.subTest(inputs=inputs):
                path.write_bytes(original)
                self.update_workflow(
                    "ci-deep.yml",
                    lambda doc, inputs=inputs: doc["on"]["workflow_dispatch"].update(
                        inputs=inputs
                    ),
                )
                self.assertIn(
                    "missing or invalid manual fuzz_seconds default",
                    policy.check(self.root),
                )
        for default in ("1", "00001", "3600", "86400", 3600):
            with self.subTest(default=default):
                path.write_bytes(original)
                self.update_workflow(
                    "ci-deep.yml",
                    lambda doc, default=default: doc["on"]["workflow_dispatch"][
                        "inputs"
                    ]["fuzz_seconds"].update(default=default),
                )
                self.assertEqual(policy.check(self.root), [])

    def test_required_soak_failure_propagation(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_bytes()
        for name in ("memcheck", "helgrind"):
            for value in (False, True, "${{ true }}"):
                with self.subTest(name=name, value=value):
                    path.write_bytes(original)
                    self.update_workflow(
                        "ci-deep.yml",
                        lambda doc, name=name, value=value: next(
                            step
                            for step in doc["jobs"][name]["steps"]
                            if "ci/tools/soak.sh" in step.get("run", "")
                        ).update({"continue-on-error": value}),
                    )
                    expected = (
                        [] if value is False else [f"{name} soak can suppress failure"]
                    )
                    self.assertEqual(policy.check(self.root), expected)
        path.write_bytes(original)
        for name in ("memcheck", "helgrind"):
            self.update_workflow(
                "ci-deep.yml",
                lambda doc, name=name: doc["jobs"][name]["steps"].append(
                    {
                        "name": "Notify",
                        "if": "failure()",
                        "continue-on-error": True,
                        "run": "echo notification",
                    }
                ),
            )
        self.assertEqual(policy.check(self.root), [])

    def test_required_soak_jobs_cannot_suppress_failure(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_bytes()
        for name in ("memcheck", "helgrind"):
            for value in (False, True, "false", "${{ false }}", "${{ true }}"):
                with self.subTest(name=name, value=value):
                    path.write_bytes(original)
                    self.update_workflow(
                        "ci-deep.yml",
                        lambda doc, name=name, value=value: doc["jobs"][name].update(
                            {"continue-on-error": value}
                        ),
                    )
                    expected = (
                        [] if value is False else [f"{name} job can suppress failure"]
                    )
                    self.assertEqual(policy.check(self.root), expected)

    def test_basic_test_command_required(self):
        path = self.root / ".github/workflows/build-test.yml"
        original = path.read_bytes()
        for command in (
            "echo skipped",
            "# prove -v ci/t/basic.t",
            "echo prove ci/t/basic.t",
            "prove -v ci/t/other.t",
            "prove -e ci/t/basic.t",
            "prove -v ci/t/basic.t || true",
        ):
            with self.subTest(command=command):
                path.write_bytes(original)
                self.replace("build-test.yml", "prove -v ci/t/basic.t", command)
                self.assertIn(
                    "required basic.t command missing", policy.check(self.root)
                )
                path.write_bytes(original)
        self.assertEqual(policy.check(self.root), [])
        self.replace("build-test.yml", "prove -v ci/t/basic.t", "prove ci/t/basic.t")
        self.assertEqual(policy.check(self.root), [])

    def test_manual_fuzz_exports_validated_input(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_bytes()
        export = 'printf \'FUZZ_SECS=%s\\n\' "${FUZZ_SECONDS_INPUT}" >> "$GITHUB_ENV"'
        for replacement in (
            "true",
            export.replace("%s", "60"),
            export.replace("${FUZZ_SECONDS_INPUT}", "3600"),
            export.replace(' >> "$GITHUB_ENV"', ""),
            "# " + export,
        ):
            with self.subTest(replacement=replacement):
                path.write_bytes(original)
                self.replace("ci-deep.yml", export, replacement)
                self.assertIn(
                    "lost validated manual fuzz duration", policy.check(self.root)
                )
                path.write_bytes(original)
        for before, after in (
            ("grep -qzE", "grep -qE"),
            ("-lt 1", "-lt 0"),
            ("-gt 86400", "-gt 99999"),
            ("{1,5}", "+"),
            ("exit 1", "true"),
        ):
            with self.subTest(before=before):
                path.write_bytes(original)
                self.replace("ci-deep.yml", before, after)
                self.assertIn(
                    "lost validated manual fuzz duration", policy.check(self.root)
                )
                path.write_bytes(original)
        self.assertEqual(policy.check(self.root), [])

    def test_manual_fuzz_input_bindings_required(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_bytes()
        for env in (
            None,
            [],
            {},
            {"FUZZ_SECONDS_INPUT": "3600", "EVENT_NAME": "${{ github.event_name }}"},
            {
                "FUZZ_SECONDS_INPUT": "${{ github.event.inputs.fuzz_seconds }}",
                "EVENT_NAME": "schedule",
            },
        ):
            with self.subTest(env=env):
                path.write_bytes(original)
                self.update_workflow(
                    "ci-deep.yml",
                    lambda doc, env=env: next(
                        step
                        for step in doc["jobs"]["fuzz"]["steps"]
                        if step.get("name") == "Select fuzz duration"
                    ).update(env=env),
                )
                self.assertIn(
                    "lost validated manual fuzz duration", policy.check(self.root)
                )
        path.write_bytes(original)
        self.assertEqual(policy.check(self.root), [])

    def update_workflow(self, name, update):
        doc = policy.load(self.root, name)
        update(doc)
        (self.root / ".github/workflows" / name).write_text(
            yaml.safe_dump(doc), encoding="utf-8"
        )

    def test_later_pr_callers_require_cancellation_guard(self):
        for caller in policy.PR_JOBS.keys() - {"build-test", "lint"}:
            with self.subTest(caller=caller):
                path = self.root / ".github/workflows/ci.yml"
                original = path.read_bytes()
                self.update_workflow(
                    "ci.yml", lambda doc, caller=caller: doc["jobs"][caller].pop("if")
                )
                self.assertIn(f"missing PR gate: {caller}", policy.check(self.root))
                path.write_bytes(original)
        self.assertEqual(policy.check(self.root), [])

    def test_basic_test_disabled_condition_rejected(self):
        for condition in (False, "false", "${{ false }}", "failure()", None):
            with self.subTest(condition=condition):
                self.update_workflow(
                    "build-test.yml",
                    lambda doc, condition=condition: next(
                        step
                        for step in doc["jobs"]["test-nginx"]["steps"]
                        if step.get("name") == "Run ci/t/basic.t"
                    ).update({"if": condition}),
                )
                self.assertIn(
                    "required basic.t step cannot run", policy.check(self.root)
                )

    def test_selector_must_precede_budget(self):
        def update(doc):
            steps = doc["jobs"]["fuzz"]["steps"]
            selector = next(
                step for step in steps if step.get("name") == "Select fuzz duration"
            )
            steps.remove(selector)
            preflight = next(
                i
                for i, step in enumerate(steps)
                if step.get("name") == "Check total fuzz job budget"
            )
            steps.insert(preflight + 1, selector)

        self.update_workflow("ci-deep.yml", update)
        self.assertIn(
            "fuzz duration selected after budget preflight", policy.check(self.root)
        )

    def test_comment_only_soak_rejected(self):
        for name in ("memcheck", "helgrind"):

            def update(doc, name=name):
                step = next(
                    step
                    for step in doc["jobs"][name]["steps"]
                    if "ci/tools/soak.sh" in step.get("run", "")
                )
                step["run"] = "\n".join(
                    "# " + line for line in step["run"].splitlines()
                )

            self.update_workflow("ci-deep.yml", update)
            self.assertIn(f"lost {name} full duration", policy.check(self.root))

    def test_pr_target_event_rejected(self):
        self.update_workflow(
            "ci.yml", lambda doc: doc["on"].update(pull_request_target={})
        )
        self.assertIn(
            "unexpected PR entry point: pull_request_target", policy.check(self.root)
        )
        self.update_workflow("ci.yml", lambda doc: doc["on"].pop("pull_request_target"))
        self.assertEqual(policy.check(self.root), [])

    def test_basic_test_failure_must_propagate(self):
        def update(doc, value):
            next(
                step
                for step in doc["jobs"]["test-nginx"]["steps"]
                if step.get("name") == "Run ci/t/basic.t"
            )["continue-on-error"] = value

        for value in (True, "${{ true }}", "false"):
            with self.subTest(value=value):
                self.update_workflow(
                    "build-test.yml", lambda doc, value=value: update(doc, value)
                )
                self.assertIn(
                    "required basic.t step can suppress failure",
                    policy.check(self.root),
                )
        self.update_workflow("build-test.yml", lambda doc: update(doc, False))
        self.assertEqual(policy.check(self.root), [])

    def test_scheduled_fuzz_export_ignores_stale_literal(self):
        self.replace(
            "ci-deep.yml",
            "printf 'FUZZ_SECS=3600",
            "# FUZZ_SECS=3600 retained comment\n            printf 'FUZZ_SECS=60",
        )
        self.assertIn("lost full fuzz duration", policy.check(self.root))

    def test_scheduled_fuzz_export_requires_environment_destination(self):
        self.replace(
            "ci-deep.yml",
            "printf 'FUZZ_SECS=3600\\n' >> \"$GITHUB_ENV\"",
            "printf 'FUZZ_SECS=3600\\n'",
        )
        self.assertIn("lost full fuzz duration", policy.check(self.root))

    def test_soak_modes_and_healthy_execution(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text(encoding="utf-8")
        for name, variable in (
            ("memcheck", "USE_VALGRIND"),
            ("helgrind", "USE_HELGRIND"),
        ):
            for field, value, error in (
                ("env", {}, f"lost {name} instrumentation"),
                ("env", {variable: "0"}, f"lost {name} instrumentation"),
                ("if", "failure()", f"{name} soak cannot run on healthy monthly run"),
                ("if", False, f"{name} soak cannot run on healthy monthly run"),
            ):
                with self.subTest(name=name, field=field, value=value):
                    self.update_workflow(
                        "ci-deep.yml",
                        lambda doc, name=name, field=field, value=value: next(
                            step
                            for step in doc["jobs"][name]["steps"]
                            if "ci/tools/soak.sh" in step.get("run", "")
                        ).update({field: value}),
                    )
                    self.assertIn(error, policy.check(self.root))
                    path.write_text(original, encoding="utf-8")
        self.assertEqual(
            policy.check(self.root), []
        )  # failure-only notifications remain valid

    def test_utf8_load_and_invalid_bytes(self):
        path = self.root / ".github/workflows/ci.yml"
        with mock.patch.object(
            Path, "read_text", autospec=True, side_effect=Path.read_text
        ) as read:
            policy.load(self.root, "ci.yml")
        read.assert_called_once_with(path, encoding="utf-8")
        path.write_bytes(b"# \xff\n")
        with mock.patch.object(policy, "ROOT", self.root):
            self.assertEqual(policy.main(), 2)

    def test_utf8_under_ascii_locale(self):
        path = self.root / ".github/workflows/ci.yml"
        path.write_bytes(path.read_bytes() + "\n# UTF-8 \u00e9\n".encode("utf-8"))
        code = (
            "import sys; from pathlib import Path; import check_ci_cadence as p; "
            "p.ROOT=Path(sys.argv[1]); sys.exit(p.main())"
        )
        env = fixture_environment(LC_ALL="C", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0")
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.root)],
            cwd=Path(policy.__file__).parent,
            env=env,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fixture_resolves_symlinked_tempdir_and_cleans_up(self):
        link = self.root / "tmp-link"
        link.symlink_to(self.root, target_is_directory=True)
        fixture = WorkflowFixture()
        with mock.patch.object(tempfile, "tempdir", str(link)):
            fixture.setUp()
        try:
            self.assertEqual(fixture.root, fixture.root.resolve())
            self.assertEqual(policy.check(fixture.root), [])
        finally:
            fixture.doCleanups()
        self.assertFalse(fixture.root.exists())

    def test_pr_entry_jobs_cannot_depend_on_failure_only_root(self):
        for caller in ("build-test", "lint"):
            with self.subTest(caller=caller):

                def update(doc, caller=caller):
                    doc["jobs"]["failure-root"] = {
                        "runs-on": "ubuntu-latest",
                        "if": "failure()",
                    }
                    doc["jobs"][caller]["needs"] = "failure-root"

                self.update_workflow("ci.yml", update)
                try:
                    self.assertIn(
                        f"PR entry job cannot depend on other jobs: {caller}",
                        policy.check(self.root),
                    )
                finally:
                    self.update_workflow(
                        "ci.yml",
                        lambda doc, caller=caller: doc["jobs"][caller].pop("needs"),
                    )
        self.update_workflow("ci.yml", lambda doc: doc["jobs"].pop("failure-root"))
        self.assertEqual(policy.check(self.root), [])

    def test_only_deep_workflow_may_schedule(self):
        for name in ("ci.yml", "fuzzing.yml", "windows-msvc.yml", "lint.yml"):
            with self.subTest(name=name):
                self.update_workflow(
                    name,
                    lambda doc: doc["on"].update(schedule=[{"cron": "30 3 4 * *"}]),
                )
                self.assertIn(
                    f"additional scheduled entry point: {name}", policy.check(self.root)
                )
                self.update_workflow(name, lambda doc: doc["on"].pop("schedule"))
        self.assertEqual(policy.check(self.root), [])

    def test_required_msvc_steps_must_run_when_healthy(self):
        name = "windows-msvc.yml"
        original = (self.root / ".github/workflows" / name).read_text(encoding="utf-8")
        required = (
            "Build",
            "Verify module and configuration controls",
            "Test persistence and singleton ownership",
        )
        for control in required:
            for condition in (False, "${{ false }}", "failure()"):
                with self.subTest(control=control, condition=condition):
                    self.update_workflow(
                        name,
                        lambda doc, control=control, condition=condition: next(
                            step
                            for step in doc["jobs"]["msvc"]["steps"]
                            if step.get("name") == control
                        ).update({"if": condition}),
                    )
                    self.assertIn(
                        f"MSVC native control cannot run: {control}",
                        policy.check(self.root),
                    )
                    (self.root / ".github/workflows" / name).write_text(
                        original, encoding="utf-8"
                    )
        self.assertEqual(policy.check(self.root), [])

    def test_budget_and_discovery_cannot_override_selected_duration(self):
        name = "ci-deep.yml"
        original = (self.root / ".github/workflows" / name).read_text(encoding="utf-8")
        for phase in ("Check total fuzz job budget", "Fuzz each target"):
            for duration in ("60", "3600", "${{ inputs.fuzz_seconds }}"):
                with self.subTest(phase=phase, duration=duration):
                    self.update_workflow(
                        name,
                        lambda doc, phase=phase, duration=duration: next(
                            step
                            for step in doc["jobs"]["fuzz"]["steps"]
                            if step.get("name") == phase
                        ).update(env={"FUZZ_SECS": duration}),
                    )
                    self.assertIn(
                        "fuzz phase overrides selected duration",
                        policy.check(self.root),
                    )
                    (self.root / ".github/workflows" / name).write_text(
                        original, encoding="utf-8"
                    )
        self.assertEqual(policy.check(self.root), [])

    def test_pr_trigger_requires_main_without_source_filters(self):
        for event in (
            {"branches": ["main"], "paths": ["docs/**"]},
            {"branches": ["main"], "paths-ignore": ["src/**"]},
            {"branches": ["other"]},
            {"branches-ignore": ["main"]},
            None,
        ):
            with self.subTest(event=event):
                self.set_events("ci.yml", {"pull_request": event})
                self.assertIn(
                    "PR trigger must target main without filters",
                    policy.check(self.root),
                )
        self.set_events("ci.yml", {"pull_request": {"branches": ["main"]}})
        self.assertEqual(policy.check(self.root), [])

    def test_shared_loader_preserves_boolean_job_names(self):
        self.replace(
            "ci.yml",
            "  lint:\n",
            "  on:\n    runs-on: ubuntu-latest\n  yes:\n    runs-on: ubuntu-latest\n  lint:\n",
        )
        self.assertIn("on", policy.load(self.root, "ci.yml")["jobs"])
        self.assertIn("yes", policy.load(self.root, "ci.yml")["jobs"])
        self.assertIn("ci.yml: fifth concurrent leaf", policy.check(self.root))

    def test_real_contract(self):
        self.assertEqual(policy.check(self.root), [])

    def test_snapshot_controls_are_required(self):
        self.replace(
            "build-test.yml", "  snapshot-controls:\n", "  removed-snapshot-controls:\n"
        )
        self.assertTrue(
            any(
                "lost or unexpected PR target: build-test" in error
                for error in policy.check(self.root)
            )
        )

    def test_each_workflow_parsed_once_per_check(self):
        expected = set((self.root / ".github/workflows").glob("*.y*ml"))
        with (
            mock.patch.object(
                policy, "load_workflow", wraps=policy.load_workflow
            ) as parse,
            mock.patch.object(
                Path, "read_text", autospec=True, side_effect=Path.read_text
            ) as read,
        ):
            self.assertEqual(policy.check(self.root), [])
        paths = [call.args[0] for call in read.call_args_list]
        self.assertEqual(set(paths), expected)
        self.assertEqual(parse.call_count, len(expected), "one parse per workflow")
        self.assertEqual(len(paths), len(expected), "one read per workflow")

    def test_check_reloads_changed_workflow(self):
        self.assertEqual(policy.check(self.root), [])
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        self.assertEqual(policy.check(self.root), ["lost full fuzz duration"])

    def test_public_load_is_fresh_and_preserves_errors(self):
        path = self.root / ".github/workflows/extra.yml"
        path.write_text("value: first\n", encoding="utf-8")
        first = policy.load(self.root, path.name)
        first["value"] = "caller mutation"
        self.assertEqual(policy.load(self.root, path.name), {"value": "first"})
        path.write_text("value: second\n", encoding="utf-8")
        self.assertEqual(policy.load(self.root, path.name), {"value": "second"})
        path.write_text("invalid: [", encoding="utf-8")
        with self.assertRaises(yaml.YAMLError):
            policy.load(self.root, path.name)
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            policy.load(self.root, path.name)

    def test_check_rejects_cached_recursive_and_escaping_calls(self):
        path = self.root / ".github/workflows/ci.yml"
        original = path.read_text(encoding="utf-8")
        outside = self.root / "outside.yml"
        outside.write_text(
            "jobs:\n  leaf:\n    runs-on: ubuntu-latest\n", encoding="utf-8"
        )
        (path.parent / "escape.yml").symlink_to(outside)
        for target in ("ci.yml", "../outside.yml", "escape.yml"):
            with self.subTest(target=target):
                path.write_text(
                    original + f"\n  extra:\n    uses: ./.github/workflows/{target}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    policy.GraphError, "^invalid or recursive workflow call$"
                ):
                    policy.check(self.root)
        path.write_text(original, encoding="utf-8")
        self.assertEqual(policy.check(self.root), [])

    def test_check_graph_load_errors_recover_on_next_invocation(self):
        path = self.root / ".github/workflows/build-test.yml"
        original = path.read_text(encoding="utf-8")
        for malformed in (True, False):
            with self.subTest(malformed=malformed):
                if malformed:
                    path.write_text("invalid: [", encoding="utf-8")
                else:
                    path.unlink()
                with self.assertRaises(policy.GraphError) as error:
                    policy.check(self.root)
                self.assertTrue(
                    str(error.exception).startswith(f"cannot load {path}: ")
                )
                self.assertIsInstance(
                    error.exception.__cause__,
                    yaml.YAMLError if malformed else FileNotFoundError,
                )
                path.write_text(original, encoding="utf-8")
                self.assertEqual(policy.check(self.root), [])

    def set_events(self, name, events):
        path = self.root / ".github/workflows" / name
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=WorkflowLoader)
        doc["on"] = events
        path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    def test_primary_pr_event_forms_and_exact_names(self):
        for event in (
            "pull_request",
            "pull_request_target",
            "prefix_pull_request",
            "pull_request_suffix",
        ):
            for events in (event, [event], {event: None}):
                with self.subTest(events=events):
                    self.set_events("ci.yml", events)
                    expected = (
                        ["PR trigger must target main without filters"]
                        if event == "pull_request"
                        else [
                            f"unexpected PR entry point: {event}",
                            "lost PR entry point",
                        ]
                    )
                    self.assertEqual(policy.check(self.root), expected)

    def test_additional_pr_event_forms_and_exact_names(self):
        path = self.root / ".github/workflows/extra.yaml"
        path.write_text(
            "jobs:\n  ordinary:\n    runs-on: ubuntu-latest\n", encoding="utf-8"
        )
        for event in (
            "pull_request",
            "pull_request_target",
            "prefix_pull_request",
            "pull_request_suffix",
            "prefix_pull_request_target",
            "pull_request_target_suffix",
        ):
            for events in (event, [event], {event: None}):
                with self.subTest(events=events):
                    self.set_events(path.name, events)
                    expected = (
                        ["additional PR entry point: extra.yaml"]
                        if event in ("pull_request", "pull_request_target")
                        else []
                    )
                    self.assertEqual(policy.check(self.root), expected)

    def test_codeql_schedule_event_forms_and_exact_names(self):
        for event in ("schedule", "prefix_schedule", "schedule_suffix"):
            for events in (event, [event], {event: None}):
                with self.subTest(events=events):
                    self.set_events("codeql.yml", events)
                    expected = (
                        ["duplicate CodeQL schedule"] if event == "schedule" else []
                    )
                    self.assertEqual(policy.check(self.root), expected)

    def test_monthly_events_require_configuration_mapping(self):
        for events in ("schedule", ["schedule", "workflow_dispatch"]):
            with self.subTest(events=events):
                self.set_events("ci-deep.yml", events)
                self.assertIn(
                    "monthly/manual trigger contract", policy.check(self.root)
                )

    def test_malformed_event_shapes_fail_closed(self):
        for name in ("ci.yml", "codeql.yml", "ci-deep.yml"):
            original = (self.root / ".github/workflows" / name).read_text(
                encoding="utf-8"
            )
            for events in (
                None,
                False,
                7,
                [None],
                [["pull_request"]],
                {("invalid",): None},
            ):
                with self.subTest(name=name, events=events):
                    self.set_events(name, events)
                    with mock.patch.object(policy, "ROOT", self.root):
                        self.assertEqual(policy.main(), 2)
                    (self.root / ".github/workflows" / name).write_text(
                        original, encoding="utf-8"
                    )

    def test_lost_pr_gate(self):
        self.replace("ci.yml", "  codeql:", "  renamed-codeql:")
        self.replace("ci.yml", "needs: codeql", "needs: renamed-codeql")
        self.assertIn("missing PR gate: codeql", policy.check(self.root))

    def test_lost_target(self):
        self.replace("ci-deep.yml", "python3 ci/fuzz/run.py 120", "true")
        self.assertIn(
            "lost fuzz regression/discovery or shared build", policy.check(self.root)
        )

    def test_required_fuzz_failure_suppression(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text(encoding="utf-8")
        for target in (
            "job",
            "--check-budget",
            "ci/fuzz/build.sh",
            "run.py 120",
            "--merge",
        ):
            for value in (
                "absent",
                False,
                True,
                "${{ inputs.allow_failure }}",
                "false",
                0,
                [],
                None,
            ):
                with self.subTest(target=target, value=value):
                    doc = yaml.load(original, Loader=WorkflowLoader)
                    job = doc["jobs"]["fuzz"]
                    obj = (
                        job
                        if target == "job"
                        else next(
                            step
                            for step in job["steps"]
                            if target in step.get("run", "")
                        )
                    )
                    if value != "absent":
                        obj["continue-on-error"] = value
                    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                    errors = policy.check(self.root)
                    if value == "absent" or value is False:
                        self.assertEqual(errors, [])
                    else:
                        self.assertTrue(
                            any("can suppress failure" in e for e in errors)
                        )

    def test_optional_fuzz_step_may_suppress_failure(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=WorkflowLoader)
        doc["jobs"]["fuzz"]["steps"].append(
            {"run": "echo optional", "continue-on-error": True}
        )
        path.write_text(yaml.safe_dump(doc), encoding="utf-8")
        self.assertEqual(policy.check(self.root), [])

    def test_missing_runner_class_is_rejected_for_every_fuzz_phase(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text(encoding="utf-8")
        for command in (
            'python3 ci/fuzz/run.py "$FUZZ_SECS" --runner-class "$RUNNER_ENVIRONMENT" --check-budget',
            'python3 ci/fuzz/run.py 120 --runner-class "$RUNNER_ENVIRONMENT"',
            'python3 ci/fuzz/run.py "$FUZZ_SECS" --merge --runner-class "$RUNNER_ENVIRONMENT"',
        ):
            with self.subTest(command=command):
                path.write_text(
                    original.replace(
                        command,
                        command.replace(' --runner-class "$RUNNER_ENVIRONMENT"', ""),
                    ),
                    encoding="utf-8",
                )
                self.assertIn(
                    "lost fuzz regression/discovery or shared build",
                    policy.check(self.root),
                )
        path.write_text(original, encoding="utf-8")
        self.assertEqual(policy.check(self.root), [])

    def test_budget_preflight_after_build_is_rejected(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text(encoding="utf-8")
        doc = yaml.load(original, Loader=WorkflowLoader)
        steps = doc["jobs"]["fuzz"]["steps"]
        preflight = next(
            step for step in steps if step.get("name") == "Check total fuzz job budget"
        )
        steps.remove(preflight)
        build = next(
            index
            for index, step in enumerate(steps)
            if step.get("name") == "Build fuzz targets"
        )
        steps.insert(build + 1, preflight)
        path.write_text(yaml.safe_dump(doc), encoding="utf-8")
        self.assertIn(
            "lost fuzz regression/discovery or shared build", policy.check(self.root)
        )
        path.write_text(original, encoding="utf-8")
        self.assertEqual(policy.check(self.root), [])

    def test_lost_native_control(self):
        self.replace(
            "windows-msvc.yml",
            "name: Test persistence and singleton ownership",
            "name: removed",
        )
        self.assertIn("lost MSVC native control", policy.check(self.root))

    def test_reject_pr_fuzz_and_msvc_even_renamed(self):
        for target in ("fuzzing", "windows-msvc"):
            with self.subTest(target=target):
                self.replace(
                    "ci.yml",
                    "./.github/workflows/windows.yml",
                    f"./.github/workflows/{target}.yml",
                )
                self.assertTrue(
                    any("PR-reachable fuzz/MSVC" in e for e in policy.check(self.root))
                )
                self.replace(
                    "ci.yml",
                    f"./.github/workflows/{target}.yml",
                    "./.github/workflows/windows.yml",
                )

    def test_direct_pr_entry_is_rejected(self):
        path = self.root / ".github/workflows/extra.yml"
        path.write_text(
            "on: [pull_request]\njobs:\n  fuzz:\n    uses: ./.github/workflows/fuzzing.yml\n",
            encoding="utf-8",
        )
        errors = policy.check(self.root)
        self.assertIn("additional PR entry point: extra.yml", errors)
        self.assertTrue(any("PR-reachable fuzz/MSVC" in e for e in errors))
        path.write_text(
            "on: pull_request_target\njobs:\n  msvc:\n    uses: ./.github/workflows/windows-msvc.yml\n",
            encoding="utf-8",
        )
        self.assertIn("additional PR entry point: extra.yml", policy.check(self.root))

    def test_additional_plain_pr_entry(self):
        path = self.root / ".github/workflows/extra.yaml"
        path.write_text(
            "on: [pull_request]\njobs:\n  ordinary:\n    runs-on: ubuntu-latest\n",
            encoding="utf-8",
        )
        self.assertIn("additional PR entry point: extra.yaml", policy.check(self.root))

    def test_cli_entry(self):
        with self.assertRaises(SystemExit) as exit_:
            runpy.run_path(str(Path(policy.__file__)), run_name="__main__")
        self.assertEqual(exit_.exception.code, 0)

    def test_monthly_fifth_leaf(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        with path.open("a", encoding="utf-8") as stream:
            stream.write("\n  fifth:\n    runs-on: ubuntu-latest\n")
        self.assertIn("ci-deep.yml: fifth concurrent leaf", policy.check(self.root))

    def test_bad_schedule_and_duration(self):
        self.replace("ci-deep.yml", "30 3 4 * *", "30 3 * * *")
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        errors = policy.check(self.root)
        self.assertIn("monthly/manual trigger contract", errors)
        self.assertIn("lost full fuzz duration", errors)

    def test_other_lost_coverage_and_ordering(self):
        self.replace("windows.yml", "  mingw:", "  renamed:")
        self.replace(
            "codeql.yml",
            "  workflow_dispatch: {}",
            '  schedule:\n    - cron: "47 4 4 * *"\n  workflow_dispatch: {}',
        )
        self.replace("ci-deep.yml", "    needs: msvc", "    needs: helgrind")
        self.replace("ci-deep.yml", "600 4", "60 4")
        self.replace(
            "ci-deep.yml",
            "./.github/workflows/codeql.yml",
            "./.github/workflows/windows-msvc.yml",
        )
        self.replace(
            "ci-deep.yml",
            "./.github/workflows/windows-msvc.yml  #",
            "./.github/workflows/windows.yml  #",
        )
        self.replace("ci.yml", "  pull_request:", "  push:")
        # Unexpected serial work does not exceed width but must be rejected.
        with (self.root / ".github/workflows/ci-deep.yml").open(
            "a", encoding="utf-8"
        ) as stream:
            stream.write("\n  extra:\n    needs: codeql\n    runs-on: ubuntu-latest\n")
        errors = policy.check(self.root)
        for expected in (
            "duplicate CodeQL schedule",
            "monthly ordering/diagnostics: memcheck",
            "lost monthly CodeQL",
            "missing monthly MSVC",
            "lost memcheck full duration",
            "lost helgrind full duration",
            "lost PR entry point",
            "lost or unexpected monthly target",
        ):
            self.assertIn(expected, errors)
        self.assertTrue(
            any("lost or unexpected PR target: windows" in e for e in errors)
        )

    def test_malformed_missing_and_exit_status(self):
        with mock.patch.object(policy, "ROOT", self.root):
            self.assertEqual(policy.main(), 0)
            self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
            self.assertEqual(policy.main(), 1)
            (self.root / ".github/workflows/ci-deep.yml").write_text(
                "invalid: [", encoding="utf-8"
            )
            self.assertEqual(policy.main(), 2)
            (self.root / ".github/workflows/ci-deep.yml").unlink()
            self.assertEqual(policy.main(), 2)


class StagedCadenceTests(WorkflowFixture):
    def test_fixture_baseline_ignores_global_exclusions(self):
        ignores = self.root / "global-ignore"
        ignores.write_text(".github/\n")
        config = self.root / "ignore-gitconfig"
        config.write_text(f'[core]\n\texcludesFile = "{ignores}"\n')
        fixture = StagedCadenceTests()
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config)}):
            try:
                fixture.setUp()
                tracked = fixture.git(
                    "ls-files", ".github/workflows"
                ).stdout.splitlines()
                self.assertEqual(
                    len(tracked),
                    len(list((fixture.root / ".github/workflows").iterdir())),
                )
                path = fixture.root / ".github/workflows/ci.yml"
                path.write_bytes(path.read_bytes() + b"\n# selected\n")
                fixture.git("add", "-f", str(path))
                result = fixture.lint()
                self.assertEqual(result.returncode, 0, result.stderr)
            finally:
                fixture.doCleanups()

    def test_explicit_staged_selection_checks_unchanged_index(self):
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        self.git("add", ".github/workflows/ci-deep.yml")
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
            "invalid baseline control",
        )
        self.assertEqual(self.git("diff", "--cached", "--name-only").stdout, b"")
        result = self.lint(files=(".github/workflows/ci.yml",))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"lost full fuzz duration", result.stdout + result.stderr)

    def test_only_fixture_baseline_disables_global_hooks(self):
        hooks = self.root / "global-hooks"
        hooks.mkdir()
        marker = self.root / "hook-ran"
        hook = hooks / "pre-commit"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 42\n")
        hook.chmod(0o700)
        config = self.root / "global-gitconfig"
        config.write_text(f'[core]\n\thooksPath = "{hooks}"\n')
        fixture = StagedCadenceTests()
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config)}):
            try:
                try:
                    fixture.setUp()
                except subprocess.CalledProcessError:
                    self.fail("fixture baseline ran inherited global hook")
                self.assertFalse(marker.exists(), "baseline invoked global hook")
                with self.assertRaises(subprocess.CalledProcessError):
                    fixture.git(
                        "-c",
                        "user.name=Fixture",
                        "-c",
                        "user.email=fixture@example.test",
                        "-c",
                        "commit.gpgsign=false",
                        "commit",
                        "--allow-empty",
                        "-qm",
                        "hook control",
                    )
                self.assertTrue(
                    marker.exists(), "hooks disabled beyond baseline commit"
                )
            finally:
                fixture.doCleanups()

    def setUp(self, object_format="sha1"):
        super().setUp()
        source = policy.ROOT
        for name in (
            "ci/linter/lib.sh",
            "ci/linter/run-all.sh",
            "ci/linter/lint-ci-monthly.sh",
            "ci/tools/check_ci_cadence.py",
            "ci/tools/check_ci_graph.py",
        ):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, target)
        init_args = (
            [] if object_format == "sha1" else [f"--object-format={object_format}"]
        )
        self.git("init", "-q", *init_args)
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

    def git(self, *args, **kwargs):
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            env=fixture_environment(),
            check=True,
            capture_output=True,
            **kwargs,
        )

    def lint(self, mode="staged", files=(), overrides=None, cwd=None):
        index = Path((overrides or {}).get("GIT_INDEX_FILE", self.root / ".git/index"))
        before = index.read_bytes()
        result = subprocess.run(
            [
                "bash",
                str(
                    self.root
                    / (
                        "ci/linter/run-all.sh"
                        if files
                        else "ci/linter/lint-ci-monthly.sh"
                    )
                ),
                *files,
            ],
            cwd=cwd or self.root,
            env=fixture_environment(
                LINT_MODE=mode, LINT_ONLY="ci-monthly", **(overrides or {})
            ),
            capture_output=True,
            check=False,
        )
        self.assertEqual(index.read_bytes(), before, "lint changed the raw index")
        return result

    def test_subdirectory_staged_workflow_validation(self):
        # A valid staged graph must be reconstructed from repo-root paths even
        # when cwd is ci/. Dirty worktree content must not enter the snapshot.
        path = self.root / ".github/workflows/ci.yml"
        path.write_bytes(path.read_bytes() + b"\n# staged selection\n")
        self.git("add", str(path))
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        result = self.lint(cwd=self.root / "ci")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"CI cadence: retained PR gates", result.stdout)
        self.assertNotIn(b"no staged workflow", result.stdout)
        self.git("add", ".github/workflows/ci-deep.yml")
        result = self.lint(cwd=self.root / "ci")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"lost full fuzz duration", result.stderr)

    def test_subdirectory_without_staged_workflow_skips(self):
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        result = self.lint(cwd=self.root / "ci")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"no staged workflow", result.stdout)

    def test_unmerged_sha256_workflow_fixture(self):
        fixture = StagedCadenceTests()
        try:
            try:
                fixture.setUp(object_format="sha256")
            except subprocess.CalledProcessError as error:
                if error.cmd[:2] == ["git", "init"] and (
                    b"unknown hash algorithm" in error.stderr
                    or (
                        b"unknown option" in error.stderr
                        and b"object-format" in error.stderr
                    )
                ):
                    self.skipTest("installed Git does not support SHA-256 repositories")
                raise
            blob = fixture.git("rev-parse", ":.github/workflows/ci.yml").stdout.strip()
            self.assertEqual(len(blob), 64)
            try:
                fixture.test_unmerged_workflow_is_rejected_without_index_changes()
            except subprocess.CalledProcessError as error:
                self.fail(f"SHA-256 unmerged fixture failed: {error.stderr!r}")
        finally:
            fixture.doCleanups()

    def test_explicit_nonworkflow_selection_skips_dirty_graph(self):
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        self.git("add", ".github/workflows/ci-deep.yml")
        for mode in ("all", "staged"):
            with self.subTest(mode=mode):
                result = self.lint(mode, ("ci/tools/check_ci_cadence.py",))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b"no selected workflow", result.stdout)
                self.assertEqual(
                    self.lint(mode, (".github/workflows/ci.yml",)).returncode, 1
                )

    def test_explicit_prefixed_workflow_selection_checks_graph(self):
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        self.git("add", ".github/workflows/ci-deep.yml")
        for mode in ("all", "staged"):
            for name in (
                "./.github/workflows/ci.yml",
                str(self.root / ".github/workflows/ci.yml"),
            ):
                with self.subTest(mode=mode, name=name):
                    result = self.lint(mode, (name,))
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertNotIn(b"no selected workflow", result.stdout)

    def test_skip_worktree_workflow_reads_stage_zero_blob(self):
        self.git("update-index", "--skip-worktree", ".github/workflows/windows.yml")
        (self.root / ".github/workflows/windows.yml").unlink()
        path = self.root / ".github/workflows/ci.yml"
        path.write_bytes(path.read_bytes() + b"\n# selected\n")
        self.git("add", str(path))
        result = self.lint()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sparse_index_workflows_read_stage_zero_blobs(self):
        path = self.root / ".github/workflows/ci.yml"
        content = path.read_bytes() + b"\n# staged in sparse index\n"
        self.git("sparse-checkout", "init", "--cone", "--sparse-index")
        self.git("sparse-checkout", "set", "ci")
        self.assertFalse(path.exists())
        blob = (
            self.git("hash-object", "-w", "--stdin", input=content)
            .stdout.strip()
            .decode()
        )
        self.git(
            "update-index", "--cacheinfo", f"100644,{blob},.github/workflows/ci.yml"
        )
        result = self.lint()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(path.exists(), "lint expanded the sparse worktree")

    def test_unmerged_workflow_is_rejected_without_index_changes(self):
        path = ".github/workflows/ci.yml"
        blob = self.git("rev-parse", f":{path}").stdout.strip()
        self.git(
            "update-index",
            "--index-info",
            input=b"0 "
            + b"0" * len(blob)
            + b"\t"
            + path.encode()
            + b"\n100644 "
            + blob
            + b" 2\t"
            + path.encode()
            + b"\n",
        )
        result = self.lint()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"unmerged or not a regular file", result.stderr)

    def test_explicit_production_index_is_honoured(self):
        alternate = self.root / "alternate-index"
        shutil.copyfile(self.root / ".git/index", alternate)
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        env = fixture_environment(GIT_INDEX_FILE=str(alternate))
        subprocess.run(
            ["git", "add", ".github/workflows/ci-deep.yml"],
            cwd=self.root,
            env=env,
            check=True,
        )
        self.assertEqual(self.lint().returncode, 0)
        result = self.lint(overrides={"GIT_INDEX_FILE": str(alternate)})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"lost full fuzz duration", result.stderr)

    def test_fixture_ignores_ambient_git_overrides(self):
        fixture = StagedCadenceTests()
        with mock.patch.dict(
            os.environ,
            {
                "GIT_DIR": str(self.root / "absent"),
                "GIT_WORK_TREE": str(self.root / "absent"),
                "GIT_INDEX_FILE": str(self.root / "absent-index"),
                "GIT_COMMON_DIR": str(self.root / "absent"),
            },
        ):
            try:
                try:
                    fixture.setUp()
                    result = fixture.lint("all")
                except (subprocess.CalledProcessError, OSError) as error:
                    self.fail(f"fixture inherited ambient Git overrides: {error}")
                self.assertEqual(result.returncode, 0, result.stderr)
            finally:
                fixture.doCleanups()

    def test_fixture_environment_clears_git_local_variables(self):
        local = self.git("rev-parse", "--local-env-vars").stdout.decode().splitlines()
        overrides = dict.fromkeys(local, "ambient-override")
        overrides.update(
            GIT_CONFIG_KEY_0="core.bare",
            GIT_CONFIG_VALUE_0="true",
            FIXTURE_SENTINEL="retained",
        )
        with mock.patch.dict(os.environ, overrides):
            env = fixture_environment()
            for name in overrides.keys() - {"FIXTURE_SENTINEL"}:
                self.assertNotIn(name, env)
            self.assertEqual(env["FIXTURE_SENTINEL"], "retained")
            self.assertEqual(
                fixture_environment(GIT_INDEX_FILE="explicit-index")["GIT_INDEX_FILE"],
                "explicit-index",
            )

    def test_no_staged_workflow_skips_dirty_graph(self):
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        result = self.lint()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"no staged workflow", result.stdout)
        self.assertEqual(self.lint("all").returncode, 1)

    def test_complete_staged_graph_ignores_unstaged_corruption(self):
        path = self.root / ".github/workflows/ci.yml"
        path.write_bytes(path.read_bytes() + b"\n# staged change\n")
        self.git("add", str(path))
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        result = self.lint()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lint("all").returncode, 1)

    def test_staged_defect_cannot_be_hidden_by_worktree_fix(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_bytes()
        self.replace("ci-deep.yml", "FUZZ_SECS=3600", "FUZZ_SECS=60")
        self.git("add", str(path))
        path.write_bytes(original)
        result = self.lint()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"lost full fuzz duration", result.stderr)
        self.assertEqual(self.lint("all").returncode, 0)

    def test_staged_workflow_deletion_is_checked(self):
        self.git("rm", ".github/workflows/windows.yml")
        self.assertEqual(self.lint().returncode, 2)


class HealthyPRConditionTests(WorkflowFixture):
    def set_job_condition(self, caller, name, condition):
        path = self.root / ".github/workflows" / f"{caller}.yml"
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=WorkflowLoader)
        doc["jobs"][name]["if"] = condition
        path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    def test_primary_runtime_failure_only_rejected(self):
        for condition in ("failure()", "${{ failure() }}"):
            with self.subTest(condition=condition):
                self.set_job_condition("build-test", "runtime", condition)
                self.assertIn(
                    "PR target cannot run on healthy PR: build-test/runtime",
                    policy.check(self.root),
                )

    def test_every_retained_child_requires_healthy_execution(self):
        for caller, children in policy.PR_JOBS.items():
            for name in sorted(children):
                with self.subTest(caller=caller, name=name):
                    path = self.root / ".github/workflows" / f"{caller}.yml"
                    original = path.read_text(encoding="utf-8")
                    self.set_job_condition(caller, name, "${{ failure() }}")
                    self.assertEqual(
                        policy.check(self.root),
                        [f"PR target cannot run on healthy PR: {caller}/{name}"],
                    )
                    path.write_text(original, encoding="utf-8")

    def test_supported_healthy_conditions(self):
        for condition in (
            "success()",
            "${{ success() }}",
            "always()",
            "${{ always() }}",
            "!cancelled()",
            "${{ !cancelled() }}",
            "${{  !cancelled()  }}",
        ):
            with self.subTest(condition=condition):
                self.set_job_condition("build-test", "runtime", condition)
                self.assertEqual(policy.check(self.root), [])
        self.set_job_condition(
            "asan",
            "asan-reload",
            "${{ !cancelled() && needs.asan.outputs.artifact-id != '' }}",
        )
        self.assertEqual(policy.check(self.root), [])

    def test_artifact_condition_requires_its_producer_context(self):
        self.set_job_condition(
            "build-test",
            "runtime",
            "${{ !cancelled() && needs.asan.outputs.artifact-id != '' }}",
        )
        self.assertEqual(
            policy.check(self.root),
            ["PR target cannot run on healthy PR: build-test/runtime"],
        )

    def test_artifact_condition_requires_producer_dependency(self):
        path = self.root / ".github/workflows/asan.yml"
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=WorkflowLoader)
        reload = doc["jobs"]["asan-reload"]
        for needs in (None, [], "asan", ["asan"]):
            with self.subTest(needs=needs):
                reload.pop("needs", None)
                if needs is not None:
                    reload["needs"] = needs
                self.assertEqual(
                    policy.healthy_pr_condition("asan", "asan-reload", reload),
                    needs in ("asan", ["asan"]),
                )
        reload["needs"] = ["asan"]
        path.write_text(yaml.safe_dump(doc), encoding="utf-8")
        self.assertEqual(policy.check(self.root), [])

    def test_false_and_malformed_child_conditions_fail_closed(self):
        for condition in (False, "false", "${{ false }}", None, [], {}):
            with self.subTest(condition=condition):
                self.set_job_condition("build-test", "runtime", condition)
                with self.assertRaises(policy.GraphError) as error:
                    policy.check(self.root)
                normalized = (
                    str(condition).removeprefix("${{").removesuffix("}}").strip()
                )
                self.assertEqual(
                    str(error.exception), f"unsupported job condition: {normalized}"
                )
                with mock.patch.object(policy, "ROOT", self.root):
                    self.assertEqual(policy.main(), 2)


class FuzzJobAndOrderTests(WorkflowFixture):
    def test_fuzz_job_failure_guard_rejected(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text(encoding="utf-8")
        for condition in ("failure()", "${{ failure() }}"):
            with self.subTest(condition=condition):
                doc = yaml.load(original, Loader=WorkflowLoader)
                doc["jobs"]["fuzz"]["if"] = condition
                path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                self.assertEqual(
                    policy.check(self.root),
                    ["fuzz job cannot run on healthy monthly run"],
                )

    def test_fuzz_job_supported_and_unsupported_guards(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text(encoding="utf-8")
        for condition in (
            "success()",
            "always()",
            "!cancelled()",
            "${{ !cancelled() }}",
        ):
            with self.subTest(condition=condition):
                doc = yaml.load(original, Loader=WorkflowLoader)
                doc["jobs"]["fuzz"]["if"] = condition
                path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                self.assertEqual(policy.check(self.root), [])
        for condition in (
            False,
            "false",
            "failure() || false",
            None,
            [],
            "(success())",
        ):
            with self.subTest(condition=condition):
                doc = yaml.load(original, Loader=WorkflowLoader)
                doc["jobs"]["fuzz"]["if"] = condition
                path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                with self.assertRaisesRegex(
                    policy.GraphError, "unsupported job condition"
                ):
                    policy.check(self.root)
        path.write_text(original, encoding="utf-8")
        self.assertEqual(policy.check(self.root), [])

    def test_fuzz_phase_order_and_cardinality(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text(encoding="utf-8")
        commands = FuzzStepConditionTests.COMMANDS
        ordered = (commands[3], commands[0], commands[1], commands[2])
        for action in ("swap01", "swap12", "swap23", "missing", "duplicate"):
            with self.subTest(action=action):
                doc = yaml.load(original, Loader=WorkflowLoader)
                steps = doc["jobs"]["fuzz"]["steps"]
                indices = [
                    next(
                        i for i, step in enumerate(steps) if step.get("run") == command
                    )
                    for command in ordered
                ]
                if action.startswith("swap"):
                    i, j = int(action[-2]), int(action[-1])
                    steps[indices[i]], steps[indices[j]] = (
                        steps[indices[j]],
                        steps[indices[i]],
                    )
                elif action == "missing":
                    steps.pop(indices[2])
                else:
                    steps.insert(indices[2], dict(steps[indices[2]]))
                path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                self.assertIn(
                    "lost fuzz regression/discovery or shared build",
                    policy.check(self.root),
                )
        path.write_text(original, encoding="utf-8")
        self.assertEqual(policy.check(self.root), [])


class FuzzStepConditionTests(WorkflowFixture):
    COMMANDS = (
        'bash ci/fuzz/build.sh "$GITHUB_WORKSPACE/ci/fuzz"',
        'python3 ci/fuzz/run.py 120 --runner-class "$RUNNER_ENVIRONMENT"',
        'python3 ci/fuzz/run.py "$FUZZ_SECS" --merge --runner-class "$RUNNER_ENVIRONMENT"',
        'python3 ci/fuzz/run.py "$FUZZ_SECS" --runner-class "$RUNNER_ENVIRONMENT" --check-budget',
    )

    def set_step_condition(self, command, condition):
        path = self.root / ".github/workflows/ci-deep.yml"
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=WorkflowLoader)
        for step in doc["jobs"]["fuzz"]["steps"]:
            if step.get("run") == command:
                step["if"] = condition
        path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    def test_disabled_fuzz_phases_rejected(self):
        for command in self.COMMANDS:
            for condition in (False, "false", "${{ false }}", "failure()"):
                with self.subTest(command=command, condition=condition):
                    path = self.root / ".github/workflows/ci-deep.yml"
                    original = path.read_text(encoding="utf-8")
                    self.set_step_condition(command, condition)
                    self.assertEqual(
                        policy.check(self.root),
                        [f"fuzz step cannot run on healthy monthly run: {command}"],
                    )
                    path.write_text(original, encoding="utf-8")

    def test_supported_fuzz_conditions(self):
        for command in self.COMMANDS:
            for condition in (
                True,
                "true",
                "${{ true }}",
                "success()",
                "${{ success() }}",
                "!cancelled()",
                "${{ !cancelled() }}",
                "always()",
                "${{ always() }}",
                "${{ TRUE }}",
                "SuCcEsS()",
                "  ${{ ( ! cancelled ( ) ) }}  ",
                "(success())",
                "${{ (( always ( ) )) }}",
            ):
                if (
                    command == self.COMMANDS[2]
                    and isinstance(condition, str)
                    and (
                        "cancelled" in condition.lower()
                        or "always" in condition.lower()
                    )
                ):
                    continue
                with self.subTest(command=command, condition=condition):
                    self.set_step_condition(command, condition)
                    self.assertEqual(policy.check(self.root), [])

    def test_discovery_rejects_failure_permitting_conditions(self):
        command = self.COMMANDS[2]
        for condition in ("!cancelled()", "${{ !cancelled() }}", "always()"):
            with self.subTest(condition=condition):
                self.set_step_condition(command, condition)
                self.assertEqual(
                    policy.check(self.root),
                    [f"fuzz step cannot run on healthy monthly run: {command}"],
                )

    def test_absent_condition_allowed_for_each_phase(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=WorkflowLoader)
        for step in doc["jobs"]["fuzz"]["steps"]:
            if step.get("run") in self.COMMANDS:
                with self.subTest(command=step["run"]):
                    step.pop("if", None)
                    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
                    self.assertEqual(policy.check(self.root), [])

    def test_malformed_and_unsupported_fuzz_conditions_rejected(self):
        for condition in (
            None,
            1,
            [],
            {},
            "",
            "${{ }}",
            "${{ success()",
            "success() }}",
            "((success())",
            "success() && false",
            "failure() || false",
            "${{ github.event_name == 'never' }}",
            "suc cess()",
        ):
            with self.subTest(condition=condition):
                self.set_step_condition(self.COMMANDS[1], condition)
                self.assertEqual(
                    policy.check(self.root),
                    [
                        "fuzz step cannot run on healthy monthly run: "
                        + self.COMMANDS[1]
                    ],
                )
                with mock.patch.object(policy, "ROOT", self.root):
                    self.assertEqual(policy.main(), 1)

    def test_current_defaults_and_discovery_success_guard(self):
        doc = policy.load(self.root, "ci-deep.yml")
        conditions = {
            step["run"]: step.get("if", "success()")
            for step in doc["jobs"]["fuzz"]["steps"]
            if step.get("run") in self.COMMANDS
        }
        self.assertEqual(
            conditions,
            {
                self.COMMANDS[0]: "success()",
                self.COMMANDS[1]: "success()",
                self.COMMANDS[2]: "success()",
                self.COMMANDS[3]: "success()",
            },
        )
        self.assertEqual(policy.check(self.root), [])

    def test_condition_helper_default_and_redundant_grouping(self):
        self.assertTrue(policy.healthy_fuzz_step_condition({}))
        for condition in (" ( ( true ) ) ", "${{ (success ( )) }}"):
            with self.subTest(condition=condition):
                self.assertTrue(policy.healthy_fuzz_step_condition({"if": condition}))


class FixtureCompatibilityTests(unittest.TestCase):
    def test_sha256_unsupported_errors_skip_and_release_partial_fixture(self):
        original_setup = WorkflowFixture.setUp
        roots = []

        def prepare(fixture):
            original_setup(fixture)
            roots.append(fixture.root)

        for message in (
            b"fatal: unknown hash algorithm 'sha256'",
            b"error: unknown option `object-format=sha256'",
            b"fatal: cannot mkdir: permission denied",
        ):
            with self.subTest(message=message):
                error = subprocess.CalledProcessError(
                    129, ["git", "init", "-q", "--object-format=sha256"], stderr=message
                )
                unsupported = b"permission denied" not in message
                expected = (
                    unittest.SkipTest if unsupported else subprocess.CalledProcessError
                )
                with (
                    mock.patch.object(WorkflowFixture, "setUp", new=prepare),
                    mock.patch.object(StagedCadenceTests, "git", side_effect=error),
                    self.assertRaises(expected),
                ):
                    StagedCadenceTests().test_unmerged_sha256_workflow_fixture()
                self.assertFalse(roots[-1].exists(), "partial fixture was not removed")

    def test_default_fixture_init_does_not_require_object_format_option(self):
        fixture = StagedCadenceTests()
        try:
            with mock.patch.object(fixture, "git") as git:
                fixture.setUp()
            self.assertEqual(git.call_args_list[0], mock.call("init", "-q"))
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
