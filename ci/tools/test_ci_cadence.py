#!/usr/bin/env python3
"""Positive, malformed, lost-gate and fifth-leaf cadence controls."""

import runpy
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_ci_cadence as policy
import yaml


class WorkflowFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        shutil.copytree(
            policy.ROOT / ".github/workflows", self.root / ".github/workflows"
        )

    def replace(self, name, before, after):
        path = self.root / ".github/workflows" / name
        text = path.read_text()
        self.assertIn(before, text)
        path.write_text(text.replace(before, after))


class CadenceTests(WorkflowFixture):
    def test_real_contract(self):
        self.assertEqual(policy.check(self.root), [])

    def set_events(self, name, events):
        path = self.root / ".github/workflows" / name
        doc = yaml.safe_load(path.read_text())
        doc.pop(True, None)  # PyYAML treats an unquoted "on" key as a boolean.
        doc["on"] = events
        path.write_text(yaml.safe_dump(doc))

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
                        [] if event == "pull_request" else ["lost PR entry point"]
                    )
                    self.assertEqual(policy.check(self.root), expected)

    def test_additional_pr_event_forms_and_exact_names(self):
        path = self.root / ".github/workflows/extra.yaml"
        path.write_text("jobs:\n  ordinary:\n    runs-on: ubuntu-latest\n")
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
            original = (self.root / ".github/workflows" / name).read_text()
            for events in (None, False, 7, [None], [["pull_request"]], {False: None}):
                with self.subTest(name=name, events=events):
                    self.set_events(name, events)
                    with mock.patch.object(policy, "ROOT", self.root):
                        self.assertEqual(policy.main(), 2)
                    (self.root / ".github/workflows" / name).write_text(original)

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
        original = path.read_text()
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
                    doc = yaml.safe_load(original)
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
                    path.write_text(yaml.safe_dump(doc))
                    errors = policy.check(self.root)
                    if value == "absent" or value is False:
                        self.assertEqual(errors, [])
                    else:
                        self.assertTrue(
                            any("can suppress failure" in e for e in errors)
                        )

    def test_optional_fuzz_step_may_suppress_failure(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        doc = yaml.safe_load(path.read_text())
        doc["jobs"]["fuzz"]["steps"].append(
            {"run": "echo optional", "continue-on-error": True}
        )
        path.write_text(yaml.safe_dump(doc))
        self.assertEqual(policy.check(self.root), [])

    def test_missing_runner_class_is_rejected_for_every_fuzz_phase(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text()
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
                    )
                )
                self.assertIn(
                    "lost fuzz regression/discovery or shared build",
                    policy.check(self.root),
                )
        path.write_text(original)
        self.assertEqual(policy.check(self.root), [])

    def test_budget_preflight_after_build_is_rejected(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text()
        doc = yaml.safe_load(original)
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
        path.write_text(yaml.safe_dump(doc))
        self.assertIn(
            "lost fuzz regression/discovery or shared build", policy.check(self.root)
        )
        path.write_text(original)
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
            "on: [pull_request]\njobs:\n  fuzz:\n    uses: ./.github/workflows/fuzzing.yml\n"
        )
        errors = policy.check(self.root)
        self.assertIn("additional PR entry point: extra.yml", errors)
        self.assertTrue(any("PR-reachable fuzz/MSVC" in e for e in errors))
        path.write_text(
            "on: pull_request_target\njobs:\n  msvc:\n    uses: ./.github/workflows/windows-msvc.yml\n"
        )
        self.assertIn("additional PR entry point: extra.yml", policy.check(self.root))

    def test_additional_plain_pr_entry(self):
        path = self.root / ".github/workflows/extra.yaml"
        path.write_text(
            "on: [pull_request]\njobs:\n  ordinary:\n    runs-on: ubuntu-latest\n"
        )
        self.assertIn("additional PR entry point: extra.yaml", policy.check(self.root))

    def test_cli_entry(self):
        with self.assertRaises(SystemExit) as exit_:
            runpy.run_path(str(Path(policy.__file__)), run_name="__main__")
        self.assertEqual(exit_.exception.code, 0)

    def test_monthly_fifth_leaf(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        with path.open("a") as stream:
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
        with (self.root / ".github/workflows/ci-deep.yml").open("a") as stream:
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
            (self.root / ".github/workflows/ci-deep.yml").write_text("invalid: [")
            self.assertEqual(policy.main(), 2)
            (self.root / ".github/workflows/ci-deep.yml").unlink()
            self.assertEqual(policy.main(), 2)


class HealthyPRConditionTests(WorkflowFixture):
    def set_job_condition(self, caller, name, condition):
        path = self.root / ".github/workflows" / f"{caller}.yml"
        doc = yaml.safe_load(path.read_text())
        doc["jobs"][name]["if"] = condition
        path.write_text(yaml.safe_dump(doc))

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
                    original = path.read_text()
                    self.set_job_condition(caller, name, "${{ failure() }}")
                    self.assertEqual(
                        policy.check(self.root),
                        [f"PR target cannot run on healthy PR: {caller}/{name}"],
                    )
                    path.write_text(original)

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
        doc = yaml.safe_load(path.read_text())
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
        path.write_text(yaml.safe_dump(doc))
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
        original = path.read_text()
        for condition in ("failure()", "${{ failure() }}"):
            with self.subTest(condition=condition):
                doc = yaml.safe_load(original)
                doc["jobs"]["fuzz"]["if"] = condition
                path.write_text(yaml.safe_dump(doc))
                self.assertEqual(
                    policy.check(self.root),
                    ["fuzz job cannot run on healthy monthly run"],
                )

    def test_fuzz_job_supported_and_unsupported_guards(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text()
        for condition in (
            "success()",
            "always()",
            "!cancelled()",
            "${{ !cancelled() }}",
        ):
            with self.subTest(condition=condition):
                doc = yaml.safe_load(original)
                doc["jobs"]["fuzz"]["if"] = condition
                path.write_text(yaml.safe_dump(doc))
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
                doc = yaml.safe_load(original)
                doc["jobs"]["fuzz"]["if"] = condition
                path.write_text(yaml.safe_dump(doc))
                with self.assertRaisesRegex(
                    policy.GraphError, "unsupported job condition"
                ):
                    policy.check(self.root)
        path.write_text(original)
        self.assertEqual(policy.check(self.root), [])

    def test_fuzz_phase_order_and_cardinality(self):
        path = self.root / ".github/workflows/ci-deep.yml"
        original = path.read_text()
        commands = FuzzStepConditionTests.COMMANDS
        ordered = (commands[3], commands[0], commands[1], commands[2])
        for action in ("swap01", "swap12", "swap23", "missing", "duplicate"):
            with self.subTest(action=action):
                doc = yaml.safe_load(original)
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
                path.write_text(yaml.safe_dump(doc))
                self.assertIn(
                    "lost fuzz regression/discovery or shared build",
                    policy.check(self.root),
                )
        path.write_text(original)
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
        doc = yaml.safe_load(path.read_text())
        for step in doc["jobs"]["fuzz"]["steps"]:
            if step.get("run") == command:
                step["if"] = condition
        path.write_text(yaml.safe_dump(doc))

    def test_disabled_fuzz_phases_rejected(self):
        for command in self.COMMANDS:
            for condition in (False, "false", "${{ false }}", "failure()"):
                with self.subTest(command=command, condition=condition):
                    path = self.root / ".github/workflows/ci-deep.yml"
                    original = path.read_text()
                    self.set_step_condition(command, condition)
                    self.assertEqual(
                        policy.check(self.root),
                        [f"fuzz step cannot run on healthy monthly run: {command}"],
                    )
                    path.write_text(original)

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
        doc = yaml.safe_load(path.read_text())
        for step in doc["jobs"]["fuzz"]["steps"]:
            if step.get("run") in self.COMMANDS:
                with self.subTest(command=step["run"]):
                    step.pop("if", None)
                    path.write_text(yaml.safe_dump(doc))
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


if __name__ == "__main__":
    unittest.main()
