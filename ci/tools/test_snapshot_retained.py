#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Compile production restore accounting and allocator/eviction paths.

Requires --core pointing to a configured nginx/Angie tree. Tests only the
post-validation restore phase, with deterministic slab capacity/failure and
clock boundaries. --negative-controls rebuilds a processed-record reporting
mutant and requires the constrained and duplicate count assertions to fail.
"""

import argparse
import hashlib
import os
import pathlib
import shlex
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
CASES = (
    "sufficient",
    "constrained",
    "duplicates",
    "readmitted",
    "protected-error",
    "first-error",
    "evict-error",
    "duplicate-error",
    "expired",
    "inactive-records",
    "empty",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=pathlib.Path, required=True)
    parser.add_argument("--negative-controls", action="store_true")
    args = parser.parse_args()
    core = args.core.resolve()
    source = (ROOT / "src/ngx_http_error_abuse_module.c").read_text()

    def function(name):
        start = source.index(f"\n{name}(")
        start = source.rindex("\nstatic ", 0, start) + 1
        return source[start : source.index("\n}\n", start) + 3]

    marker = "} ngx_http_error_abuse_node_t;"
    end = source.index(marker) + len(marker)
    node = source[source.rindex("typedef struct {", 0, end) : end]
    helpers = "\n".join(
        function("ngx_http_error_abuse_" + name)
        for name in (
            "events",
            "node_size",
            "lookup",
            "touch",
            "delete",
            "expire",
            "evict_one_unblocked",
            "slab_alloc_locked",
            "create_node",
            "rbtree_insert",
        )
    )
    load = function("ngx_http_error_abuse_load")
    body = load[load.index("    now = ngx_time();") : load.rindex("\n}")]
    template = (ROOT / "ci/tests/unit/test_snapshot_retained.c.in").read_text()
    template = template.replace("/* NODE_LAYOUT */", node).replace(
        "/* NODE_HELPERS */", helpers
    )
    with tempfile.TemporaryDirectory(prefix="snapshot-retained-") as directory:
        build = pathlib.Path(directory)

        def compile_body(restore, label):
            generated = build / f"{label}.c"
            generated.write_text(template.replace("/* RESTORE_BODY */", restore))
            binary = build / label
            command = [
                *shlex.split(os.environ.get("CC", "cc")),
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-ffunction-sections",
                "-fdata-sections",
                "-Wl,--gc-sections",
                *[
                    f"-I{core / p}"
                    for p in ("src/core", "src/event", "src/os/unix", "objs")
                ],
                f"-I{ROOT / 'src'}",
                str(generated),
                str(ROOT / "src/ngx_http_error_abuse_scan.c"),
                str(core / "src/core/ngx_string.c"),
                str(core / "src/core/ngx_rbtree.c"),
                str(core / "src/core/ngx_crc32.c"),
                "-o",
                str(binary),
            ]
            print(shlex.join(command), flush=True)
            subprocess.run(command, check=True)
            info = binary.stat()
            print(
                f"binary={binary} mtime_ns={info.st_mtime_ns} size={info.st_size} "
                f"sha256={hashlib.sha256(binary.read_bytes()).hexdigest()}",
                flush=True,
            )
            return binary

        def run(binary, name):
            command = [str(binary), name]
            print(shlex.join(command), flush=True)
            result = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            print(result.stdout + result.stderr, end="", flush=True)
            return result

        binary = compile_body(body, "green")
        for name in CASES:
            run(binary, name).check_returncode()
        if args.negative_controls:
            marker = "loaded = retained;"
            if body.count(marker) != 1:
                raise AssertionError("expected one final retained assignment")
            mutant = compile_body(
                body.replace(marker, "loaded = record_index;"), "processed-mutant"
            )
            for name in ("constrained", "duplicates"):
                result = run(mutant, name)
                if result.returncode != 1 or result.stderr.strip() != (
                    "FAIL: restored count differs from retained identities"
                ):
                    raise AssertionError(f"{name}: reporting mutant not observed red")
                print(f"OK: {name} reporting mutant observed red", flush=True)
            restored = compile_body(body, "restored")
            for name in CASES:
                run(restored, name).check_returncode()


if __name__ == "__main__":
    main()
