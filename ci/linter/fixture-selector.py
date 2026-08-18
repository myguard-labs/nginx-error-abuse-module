#!/usr/bin/env python3
"""Render the approved runner selector into a temporary positive fixture."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent


def approved_selector() -> str | None:
    spec = importlib.util.spec_from_file_location(
        "workflow_policy", HERE / "workflow_policy.py"
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not getattr(mod, "SELF_HOSTED_ALLOWED", False):
        return None
    return mod.APPROVED_SELECTOR


def main(argv: list[str]) -> int:
    selector = approved_selector()
    if selector is None:
        return 1

    if len(argv) >= 2 and argv[0] == "--write":
        path = pathlib.Path(argv[1])
        text = path.read_text(encoding="utf-8")
        new, count = re.subn(
            r"(?m)^(\s*runs-on: ).*$",
            lambda match: match.group(1) + selector,
            text,
            count=1,
        )
        if count != 1:
            print(f"{path}: no runs-on: line to rewrite", file=sys.stderr)
            return 1
        if new != text:
            path.write_text(new, encoding="utf-8")
        return 0

    print(selector)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
