#!/usr/bin/env python3
"""Tests for the conservative PR graph width proof."""

import itertools
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_ci_graph
from check_ci_graph import GraphError, graph, width


class MatrixTests(unittest.TestCase):
    def size(self, matrix):
        return check_ci_graph.matrix_size({"strategy": {"matrix": matrix}})

    def test_static_matrices_without_cartesian_product(self):
        with mock.patch.object(
            itertools,
            "product",
            side_effect=AssertionError("Cartesian product must not be invoked"),
        ):
            self.assertEqual(check_ci_graph.matrix_size({}), 1)
            self.assertEqual(
                self.size({"os": ["linux", "windows"], "cc": ["gcc", "clang"]}), 4
            )
            self.assertEqual(
                self.size({"include": [{"os": "linux"}, {"os": "windows"}]}), 2
            )
            self.assertEqual(self.size({"axis": [None, True, 1, 1.5, "static"]}), 5)
            # Even an include that only amends a combination contributes a row.
            self.assertEqual(
                self.size({"os": ["linux"], "include": [{"os": "linux"}]}), 2
            )

    def test_matrix_limit_boundaries(self):
        for matrix in (
            {"axis": list(range(256))},
            {"a": list(range(16)), "b": list(range(16))},
            {"axis": list(range(255)), "include": [{"extra": True}]},
            {"include": [{"slot": i} for i in range(256)]},
        ):
            with self.subTest(matrix=matrix):
                self.assertEqual(self.size(matrix), 256)
        for matrix in (
            {"axis": list(range(257))},
            {"a": list(range(16)), "b": list(range(16)), "include": [{"extra": True}]},
            {"axis": list(range(255)), "include": [{"extra": True}, {"extra": False}]},
            {"include": [{"slot": i} for i in range(257)]},
        ):
            with (
                self.subTest(matrix=matrix),
                self.assertRaisesRegex(GraphError, "empty or oversized matrix"),
            ):
                self.size(matrix)

    def test_oversized_axes_rejected_without_cartesian_product(self):
        # This input would expand to 64 million combinations.
        matrix = {name: list(range(400)) for name in ("a", "b", "c")}
        with (
            mock.patch.object(
                itertools,
                "product",
                side_effect=AssertionError("Cartesian product must not be invoked"),
            ),
            self.assertRaisesRegex(GraphError, "empty or oversized matrix"),
        ):
            self.size(matrix)

    def test_values_validated_before_size_limit(self):
        for value in ("${{ inputs.axis }}", {"nested": "value"}, ["nested"]):
            for large in (False, True):
                axes = {"a": list(range(400)), "b": list(range(400))} if large else {}
                for field in ("axis", "include"):
                    matrix = dict(axes)
                    matrix.update(
                        {"invalid": [value]}
                        if field == "axis"
                        else {
                            "include": [{"invalid": value}],
                        }
                    )
                    with (
                        self.subTest(value=value, large=large, field=field),
                        mock.patch.object(
                            itertools,
                            "product",
                            side_effect=AssertionError(
                                "Cartesian product must not be invoked"
                            ),
                        ),
                        self.assertRaisesRegex(GraphError, f"dynamic matrix {field}"),
                    ):
                        self.size(matrix)

    def test_empty_and_malformed_matrices(self):
        for matrix in ({}, {"include": []}):
            with (
                self.subTest(matrix=matrix),
                self.assertRaisesRegex(GraphError, "empty or oversized matrix"),
            ):
                self.size(matrix)
        for axis in ([], "dynamic", {"nested": "value"}, None, 1, ()):
            with (
                self.subTest(axis=axis),
                self.assertRaisesRegex(GraphError, "dynamic or empty matrix"),
            ):
                self.size({"axis": axis})
        for include in (None, "dynamic", {}, ["invalid"], [[]]):
            with (
                self.subTest(include=include),
                self.assertRaisesRegex(GraphError, "invalid matrix include"),
            ):
                self.size({"axis": [1], "include": include})


class WidthTests(unittest.TestCase):
    def test_empty_chain_and_parallel_boundaries(self):
        self.assertEqual(width({}), [])
        self.assertEqual(len(width({"a": set()})), 1)
        self.assertEqual(len(width({"a": set(), "b": {"a"}, "c": {"a", "b"}})), 1)
        for size in (4, 5):
            with self.subTest(size=size):
                self.assertEqual(len(width({str(i): set() for i in range(size)})), size)

    def test_matches_exhaustive_oracle_on_small_dags(self):
        nodes = list("abcde")
        possible_edges = list(itertools.combinations(nodes, 2))
        for mask in range(1 << len(possible_edges)):
            ancestors = {node: set() for node in nodes}
            for bit, (earlier, later) in enumerate(possible_edges):
                if mask & (1 << bit):
                    ancestors[later].add(earlier)
            for node in nodes:
                for dep in list(ancestors[node]):
                    ancestors[node].update(ancestors[dep])
            expected = max(
                len(group)
                for size in range(len(nodes) + 1)
                for group in itertools.combinations(nodes, size)
                if all(
                    a not in ancestors[b] and b not in ancestors[a]
                    for a, b in itertools.combinations(group, 2)
                )
            )
            with self.subTest(mask=mask):
                witness = width(ancestors)
                self.assertEqual(len(witness), expected)
                self.assertEqual(len(set(witness)), len(witness))
                self.assertTrue(set(witness) <= ancestors.keys())
                self.assertTrue(
                    all(
                        a not in ancestors[b] and b not in ancestors[a]
                        for a, b in itertools.combinations(witness, 2)
                    )
                )


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.workflows = self.root / ".github/workflows"
        self.workflows.mkdir(parents=True)

    def write(self, name, body):
        if name != "ci.yml" and body.startswith("jobs:"):
            body = "on: workflow_call\n" + body
        (self.workflows / name).write_text(body)

    def test_fixture_resolves_symlinked_tempdir_and_cleans_up(self):
        link = self.root / "tmp-link"
        link.symlink_to(self.root, target_is_directory=True)
        fixture = GraphTests()
        with mock.patch.object(tempfile, "tempdir", str(link)):
            fixture.setUp()
        try:
            self.assertEqual(fixture.root, fixture.root.resolve())
            fixture.test_loader_cannot_bypass_confinement_or_recursion()
        finally:
            fixture.doCleanups()
        self.assertFalse(fixture.root.exists())

    def test_loader_rejects_python_object_tags(self):
        self.write("ci.yml", "!!python/object/apply:builtins.eval ['1 + 1']")
        with self.assertRaisesRegex(GraphError, "cannot load") as caught:
            graph(self.root)
        self.assertIsInstance(caught.exception.__cause__, check_ci_graph.yaml.YAMLError)

    def test_invalid_utf8_uses_load_error_path(self):
        (self.workflows / "ci.yml").write_bytes(b"# \xff\n")
        with self.assertRaisesRegex(GraphError, "cannot load"):
            graph(self.root)
        with mock.patch.object(check_ci_graph, "ROOT", self.root):
            self.assertEqual(check_ci_graph.main(), 2)

    def test_real_graph(self):
        self.assertLessEqual(len(width(graph(Path(__file__).resolve().parents[2]))), 4)

    def test_optional_loader_preserves_expansion_and_standalone_freshness(self):
        self.write(
            "ci.yml",
            "jobs:\n  call:\n    uses: ./.github/workflows/child.yml\n"
            "    strategy:\n      matrix:\n        slot: [one, two]\n",
        )
        self.write("child.yml", "jobs:\n  leaf:\n    runs-on: ubuntu-latest\n")
        expected = {"call[0]/leaf[0]": set(), "call[1]/leaf[0]": set()}
        loader = mock.Mock(
            side_effect=lambda path: check_ci_graph.yaml.safe_load(path.read_text())
        )
        self.assertEqual(graph(self.root, document_loader=loader), expected)
        self.assertEqual(
            [call.args[0].name for call in loader.call_args_list],
            ["ci.yml", "child.yml", "child.yml"],
        )
        self.assertEqual(graph(self.root), expected)
        self.write("child.yml", "jobs:\n  changed:\n    runs-on: ubuntu-latest\n")
        self.assertEqual(
            graph(self.root),
            {"call[0]/changed[0]": set(), "call[1]/changed[0]": set()},
        )

    def test_loader_cannot_bypass_confinement_or_recursion(self):
        document = {"jobs": {"call": {"uses": "./.github/workflows/ci.yml"}}}
        loader = mock.Mock(return_value=document)
        with self.assertRaisesRegex(GraphError, "^invalid or recursive workflow call$"):
            graph(self.root, document_loader=loader)
        loader.assert_called_once_with(self.workflows / "ci.yml")
        for entry in ("outside.yml", ".github/workflows/../../outside.yml"):
            with self.subTest(entry=entry):
                loader.reset_mock()
                with self.assertRaisesRegex(
                    GraphError, "^invalid or recursive workflow call$"
                ):
                    graph(self.root, entry, document_loader=loader)
                loader.assert_not_called()

    def test_loader_preserves_load_error_wrapping(self):
        def loader(path):
            return check_ci_graph.yaml.safe_load(path.read_text())

        for body in (None, "invalid: [", "null", "other: value"):
            with self.subTest(body=body):
                if body is not None:
                    self.write("ci.yml", body)
                with self.assertRaises(GraphError) as standalone:
                    graph(self.root)
                with self.assertRaises(GraphError) as shared:
                    graph(self.root, document_loader=loader)
                self.assertEqual(str(shared.exception), str(standalone.exception))
                self.assertEqual(
                    type(shared.exception.__cause__),
                    type(standalone.exception.__cause__),
                )

    def test_boolean_and_null_job_ids_are_distinct(self):
        self.write(
            "ci.yml",
            "jobs:\n"
            + "".join(
                f"  {name}:\n    runs-on: ubuntu-latest\n"
                for name in ("on", "yes", "true", "null", "ordinary")
            ),
        )
        self.assertEqual(len(width(graph(self.root))), 5)
        doc = check_ci_graph.load_workflow(self.workflows / "ci.yml")
        self.assertEqual(set(doc["jobs"]), {"on", "yes", "true", "null", "ordinary"})

    def test_scalar_and_sequence_dependencies_preserve_job_ids(self):
        for name in ("on", "yes", "true", "null", "ordinary"):
            for needs in (name, f"[{name}]", f"['{name}']"):
                with self.subTest(name=name, needs=needs):
                    self.write(
                        "ci.yml",
                        "jobs:\n"
                        f"  {name}: {{runs-on: ubuntu-latest}}\n"
                        f"  after: {{runs-on: ubuntu-latest, needs: {needs}}}\n",
                    )
                    expanded = graph(self.root)
                    self.assertEqual(len(expanded), 2)
                    self.assertEqual(len(width(expanded)), 1)
                    doc = check_ci_graph.load_workflow(self.workflows / "ci.yml")
                    self.assertIn(doc["jobs"]["after"]["needs"], (name, [name]))

    def test_loader_preserves_boolean_values_and_rejects_duplicate_keys(self):
        self.write(
            "ci.yml", "jobs: {one: {runs-on: ubuntu-latest, continue-on-error: false}}"
        )
        doc = check_ci_graph.load_workflow(self.workflows / "ci.yml")
        self.assertIs(doc["jobs"]["one"]["continue-on-error"], False)
        self.write("ci.yml", "jobs: {one: {}, one: {}}")
        with self.assertRaisesRegex(GraphError, "duplicate workflow key"):
            graph(self.root)

    def test_expansion_node_budget_and_nested_matrix(self):
        for count in (8, 9):
            self.write(
                "ci.yml",
                "jobs:\n"
                + "".join(
                    f"  j{i}:\n    runs-on: ubuntu-latest\n" for i in range(count)
                ),
            )
            with mock.patch.object(check_ci_graph, "MAX_GRAPH_NODES", 8):
                if count == 8:
                    self.assertEqual(len(graph(self.root)), 8)
                else:
                    with self.assertRaisesRegex(GraphError, "node budget"):
                        graph(self.root)
        self.write(
            "ci.yml",
            "jobs:\n  call:\n    uses: ./.github/workflows/child.yml\n    strategy: {matrix: {slot: [1, 2, 3]}}\n",
        )
        self.write(
            "child.yml",
            "jobs:\n  leaf:\n    runs-on: ubuntu-latest\n    strategy: {matrix: {slot: [1, 2, 3]}}\n",
        )
        with (
            mock.patch.object(check_ci_graph, "MAX_GRAPH_NODES", 8),
            self.assertRaisesRegex(GraphError, "node budget"),
        ):
            graph(self.root)

    def test_dependency_and_ancestor_budgets(self):
        self.write(
            "ci.yml",
            "jobs:\n  first:\n    runs-on: ubuntu-latest\n    strategy: {matrix: {slot: [1, 2]}}\n  second:\n    runs-on: ubuntu-latest\n    needs: first\n    strategy: {matrix: {slot: [1, 2]}}\n",
        )
        with mock.patch.object(check_ci_graph, "MAX_GRAPH_RELATIONS", 4):
            self.assertEqual(len(width(graph(self.root))), 2)
        with (
            mock.patch.object(check_ci_graph, "MAX_GRAPH_RELATIONS", 3),
            self.assertRaisesRegex(GraphError, "edge budget"),
        ):
            graph(self.root)
        self.write(
            "ci.yml",
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n  b:\n    runs-on: ubuntu-latest\n    needs: a\n  c:\n    runs-on: ubuntu-latest\n    needs: b\n",
        )
        with mock.patch.object(check_ci_graph, "MAX_GRAPH_RELATIONS", 3):
            self.assertEqual(len(width(graph(self.root))), 1)
        with (
            mock.patch.object(check_ci_graph, "MAX_GRAPH_RELATIONS", 2),
            self.assertRaisesRegex(GraphError, "ancestor budget"),
        ):
            graph(self.root)

    def test_four_and_injected_fifth_leaf(self):
        self.write(
            "ci.yml",
            "jobs:\n"
            + "".join(f"  j{i}:\n    runs-on: ubuntu-latest\n" for i in range(4)),
        )
        self.assertEqual(len(width(graph(self.root))), 4)
        with (self.workflows / "ci.yml").open("a") as stream:
            stream.write("  fifth:\n    runs-on: ubuntu-latest\n")
        self.assertEqual(len(width(graph(self.root))), 5)
        with mock.patch.object(check_ci_graph, "ROOT", self.root):
            self.assertEqual(check_ci_graph.main(), 1)

    def test_wide_staged_graph_without_subset_search(self):
        self.write(
            "ci.yml",
            "jobs:\n"
            "  first:\n    runs-on: ubuntu-latest\n"
            "    strategy:\n      matrix:\n"
            f"        slot: {list(range(32))}\n"
            "  second:\n    needs: first\n    runs-on: ubuntu-latest\n"
            "    strategy:\n      matrix:\n"
            f"        slot: {list(range(32))}\n",
        )
        ancestors = graph(self.root)
        self.assertEqual(len(ancestors), 64)
        # Fail the old exponential search before it enumerates any subsets.
        with mock.patch.object(
            itertools, "combinations", side_effect=AssertionError("subset enumeration")
        ):
            witness = width(ancestors)
            self.assertEqual(len(witness), 32)
            with mock.patch.object(check_ci_graph, "ROOT", self.root):
                self.assertEqual(check_ci_graph.main(), 1)
        self.assertTrue(
            all(
                a not in ancestors[b] and b not in ancestors[a]
                for a, b in itertools.combinations(witness, 2)
            )
        )

    def test_separate_matrix_limits_do_not_limit_aggregate(self):
        self.write(
            "ci.yml",
            """jobs:
  first:
    runs-on: ubuntu-latest
    strategy:
      max-parallel: 2
      matrix:
        os: [one, two]
  second:
    runs-on: ubuntu-latest
    strategy:
      max-parallel: 3
      matrix:
        os: [one, two, three]
""",
        )
        self.assertEqual(len(width(graph(self.root))), 5)
        with mock.patch.object(check_ci_graph, "ROOT", self.root):
            self.assertEqual(check_ci_graph.main(), 1)

    def test_nested_call_and_failure_conditions(self):
        self.write(
            "ci.yml",
            """jobs:
  caller:
    uses: ./.github/workflows/child.yml
  after:
    needs: caller
    if: always()
    runs-on: ubuntu-latest
""",
        )
        self.write(
            "child.yml",
            """jobs:
  first:
    runs-on: ubuntu-latest
  next:
    needs: first
    if: ${{ !cancelled() }}
    runs-on: ubuntu-latest
""",
        )
        self.assertEqual(len(width(graph(self.root))), 1)

    def test_reload_artifact_condition_preserves_width(self):
        self.write(
            "ci.yml",
            """jobs:
  asan:
    runs-on: ubuntu-latest
  asan-reload:
    needs: asan
    if: ${{ !cancelled() && needs.asan.outputs.artifact-id != '' }}
    runs-on: ubuntu-latest
  parallel:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        slot: [one, two, three]
""",
        )
        ancestors = graph(self.root)
        self.assertEqual(ancestors["asan-reload[0]"], {"asan[0]"})
        self.assertEqual(len(width(ancestors)), 4)
        with (self.workflows / "ci.yml").open("a") as stream:
            stream.write("  fifth:\n    runs-on: ubuntu-latest\n")
        self.assertEqual(len(width(graph(self.root))), 5)
        with mock.patch.object(check_ci_graph, "ROOT", self.root):
            self.assertEqual(check_ci_graph.main(), 1)

    def test_reload_rejects_wrong_artifact_conditions(self):
        for condition in (
            "needs.asan.outputs.artifact-id != ''",
            "success() && needs.asan.outputs.artifact-id != ''",
            "always() && needs.asan.outputs.artifact-id != ''",
            "!cancelled() || needs.asan.outputs.artifact-id != ''",
            "!cancelled() && needs.asan.outputs.artifact-id == ''",
            "!cancelled() && needs.other.outputs.artifact-id != ''",
        ):
            with self.subTest(condition=condition):
                self.write(
                    "ci.yml",
                    "jobs:\n  asan:\n    runs-on: ubuntu-latest\n"
                    "  asan-reload:\n    needs: asan\n"
                    f"    if: ${{{{ {condition} }}}}\n"
                    "    runs-on: ubuntu-latest\n",
                )
                with self.assertRaisesRegex(GraphError, "unsupported job condition"):
                    graph(self.root)

    def test_real_reload_diagnostics_condition(self):
        root = Path(__file__).resolve().parents[2]
        with mock.patch.object(
            check_ci_graph, "load_workflow", wraps=check_ci_graph.load_workflow
        ) as load:
            jobs = check_ci_graph.load_workflow(root / ".github/workflows/asan.yml")[
                "jobs"
            ]
        load.assert_called_once_with(root / ".github/workflows/asan.yml")
        self.assertEqual(jobs["asan-reload"]["needs"], "asan")
        condition = jobs["asan-reload"].get("if", "success()")
        condition = condition.removeprefix("${{").removesuffix("}}").strip()
        # Model the documented status-function override of implicit success().
        # Only the conjunction's status/artifact atoms are supported here.
        # https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions
        terms = condition.split(" && ")
        for result, artifact_id, cancelled, expected in (
            ("success", "123", False, True),
            ("failure", "123", False, True),  # Uploaded before runtime failure.
            ("success", "", False, False),
            ("failure", "", False, False),
            ("skipped", "", False, False),
            ("cancelled", "123", True, False),
            ("success", "123", True, False),  # Run cancelled after upload.
            ("failure", "", True, False),
        ):
            with self.subTest(
                result=result, artifact_id=artifact_id, cancelled=cancelled
            ):
                atoms = {
                    "success()": result == "success",
                    "failure()": result == "failure",
                    "always()": True,
                    "cancelled()": cancelled,
                    "!cancelled()": not cancelled,
                    "needs.asan.outputs.artifact-id != ''": artifact_id != "",
                }
                for term in terms:
                    self.assertIn(term, atoms, "unsupported reload condition atom")
                explicit_status = any(
                    term in atoms and term.endswith("()") for term in terms
                )
                runs = (explicit_status or result == "success") and all(
                    atoms[term] for term in terms
                )
                self.assertEqual(
                    runs, expected, f"reload diagnostic condition: {condition}"
                )

    def test_rejects_invalid_graphs(self):
        for body in (
            "jobs:\n  a:\n    needs: absent\n    runs-on: ubuntu-latest\n",
            "jobs:\n  a:\n    needs: b\n    runs-on: ubuntu-latest\n  b:\n    needs: a\n    runs-on: ubuntu-latest\n",
            "jobs:\n  a:\n    if: ${{ github.event_name == 'push' }}\n    runs-on: ubuntu-latest\n",
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix: ${{ fromJSON(inputs.matrix) }}\n",
        ):
            with self.subTest(body=body):
                self.write("ci.yml", body)
                with self.assertRaises(GraphError):
                    graph(self.root)


if __name__ == "__main__":
    unittest.main()
