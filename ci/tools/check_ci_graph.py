#!/usr/bin/env python3
"""Conservative runner-width proof for the PR orchestrator's static graph."""

import sys
from collections import deque
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class GraphError(ValueError):
    """The graph cannot be safely bounded."""


def matrix_size(job):
    strategy = job.get("strategy", {})
    if not isinstance(strategy, dict) or set(strategy) - {
        "matrix",
        "fail-fast",
        "max-parallel",
    }:
        raise GraphError("unsupported strategy")
    matrix = strategy.get("matrix")
    if matrix is None:
        return 1
    if not isinstance(matrix, dict) or "exclude" in matrix:
        raise GraphError("unsupported matrix")
    axes = {k: v for k, v in matrix.items() if k != "include"}
    if any(not isinstance(v, list) or not v for v in axes.values()):
        raise GraphError("dynamic or empty matrix")
    include = matrix.get("include", [])
    if not isinstance(include, list) or any(
        not isinstance(row, dict) for row in include
    ):
        raise GraphError("invalid matrix include")
    if any(
        isinstance(v, (dict, list)) or "${{" in str(v)
        for row in include
        for v in row.values()
    ):
        raise GraphError("dynamic matrix include")
    if any(
        isinstance(v, (dict, list)) or "${{" in str(v)
        for axis in axes.values()
        for v in axis
    ):
        raise GraphError("dynamic matrix axis")
    # Count combinations without expanding them. Include rows count even when
    # they amend a combination, preserving a conservative width bound.
    count = 1 if axes else 0
    for axis in axes.values():
        count *= len(axis)
        if count + len(include) > 256:
            raise GraphError("empty or oversized matrix")
    count += len(include)
    if not count or count > 256:
        raise GraphError("empty or oversized matrix")
    return count


def graph(root, entry=".github/workflows/ci.yml", *, document_loader=None):
    root = Path(root).resolve()
    edges = {}

    def expand(path, prefix, stack):
        path = (root / path).resolve()
        if not path.is_relative_to(root / ".github/workflows") or path in stack:
            raise GraphError("invalid or recursive workflow call")
        try:
            doc = (
                yaml.safe_load(path.read_text())
                if document_loader is None
                else document_loader(path)
            )
            jobs = doc["jobs"]
        except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
            raise GraphError(f"cannot load {path}: {exc}") from exc
        if not isinstance(jobs, dict) or not jobs:
            raise GraphError("missing jobs")
        spans = {}
        for name, job in jobs.items():
            if not isinstance(job, dict):
                raise GraphError(f"invalid job {name}")
            condition = str(job.get("if", "success()"))
            condition = condition.removeprefix("${{").removesuffix("}}").strip()
            # Conditions can only remove leaves from the antichain proof.
            # Keep the supported grammar explicit, including reload's artifact guard.
            if condition not in {
                "success()",
                "failure()",
                "always()",
                "!cancelled()",
                "!cancelled() && needs.asan.outputs.artifact-id != ''",
            }:
                raise GraphError(f"unsupported job condition: {condition}")
            size = matrix_size(job)
            starts, ends = set(), set()
            for i in range(size):
                ident = f"{prefix}{name}[{i}]"
                if "uses" in job:
                    target = job["uses"]
                    if not isinstance(target, str) or not target.startswith(
                        "./.github/workflows/"
                    ):
                        raise GraphError("unsupported reusable workflow")
                    child_starts, child_ends = expand(
                        target[2:], ident + "/", stack + (path,)
                    )
                    starts.update(child_starts)
                    ends.update(child_ends)
                elif "runs-on" in job:
                    edges[ident] = set()
                    starts.add(ident)
                    ends.add(ident)
                else:
                    raise GraphError(f"job {name} has no runner or local call")
            spans[name] = (starts, ends)
        for name, job in jobs.items():
            needs = job.get("needs", [])
            if isinstance(needs, str):
                needs = [needs]
            if not isinstance(needs, list) or any(n not in spans for n in needs):
                raise GraphError(f"invalid needs for {name}")
            for dep in needs:
                for node in spans[name][0]:
                    edges[node].update(spans[dep][1])
        all_starts = set().union(*(s for s, _ in spans.values()))
        all_ends = set().union(*(e for _, e in spans.values()))
        internal = set().union(*(edges[n] for n in all_starts))
        return {n for n in all_starts if not edges[n]}, all_ends - internal

    expand(entry, "", ())
    ancestors = {}

    def visit(node, active):
        if node in active:
            raise GraphError("dependency cycle")
        if node not in ancestors:
            ancestors[node] = set(edges[node])
            for dep in edges[node]:
                ancestors[node].update(visit(dep, active | {node}))
        return ancestors[node]

    for node in edges:
        visit(node, set())
    return ancestors


def _augment(start, dependencies, left_match, right_match):
    # Find an alternating path to an unmatched right vertex without recursion.
    pending = deque([start])
    seen = {start}
    parents = {}
    end = None
    while pending:
        node = pending.popleft()
        for dep in dependencies[node]:
            if dep in parents:
                continue
            parents[dep] = node
            if dep not in right_match:
                end = dep
                break
            matched = right_match[dep]
            if matched not in seen:
                seen.add(matched)
                pending.append(matched)
        if end is not None:
            break
    while end is not None:
        node = parents[end]
        previous = left_match.get(node)
        left_match[node] = end
        right_match[end] = node
        end = previous


def width(ancestors):
    # Dilworth's theorem: a maximum matching of the transitive dependency
    # relation gives the minimum chain cover and thus the exact antichain width.
    dependencies = {node: sorted(deps) for node, deps in ancestors.items()}
    left_match, right_match = {}, {}
    for node in dependencies:
        _augment(node, dependencies, left_match, right_match)

    # Alternating reachability gives a minimum vertex cover (Konig's theorem).
    # Nodes outside that cover on both sides form a maximum antichain.
    reachable_left = set(dependencies) - left_match.keys()
    reachable_right = set()
    pending = deque(sorted(reachable_left))
    while pending:
        node = pending.popleft()
        for dep in dependencies[node]:
            if dep == left_match.get(node) or dep in reachable_right:
                continue
            reachable_right.add(dep)
            if dep in right_match and right_match[dep] not in reachable_left:
                reachable_left.add(right_match[dep])
                pending.append(right_match[dep])
    return [
        node
        for node in dependencies
        if node in reachable_left and node not in reachable_right
    ]


def main():
    try:
        witness = width(graph(ROOT))
        print(f"PR leaf width <= {len(witness)}: {', '.join(witness)}")
        return int(len(witness) > 4)
    except GraphError as exc:
        print(f"CI graph error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
