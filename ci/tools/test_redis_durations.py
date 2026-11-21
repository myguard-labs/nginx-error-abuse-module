#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Compile the exact Redis record function at time32 and native field widths.

No nginx/Redis process or multilib libc is required. UBSan checks the actual
production arithmetic; the fixture substitutes only external API boundaries.
Use --negative-controls to remove each widening in turn and require UBSan red.
"""

import argparse
import os
import pathlib
import re
import shlex
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--negative-controls", action="store_true")
    args = parser.parse_args()
    source = (ROOT / "src/ngx_http_error_abuse_module.c").read_text()
    start = source.index("static void\nngx_http_error_abuse_redis_record(")
    record = source[start : source.index("\n}\n", start) + 3]
    maximum = re.search(r"#define NGX_HTTP_ERROR_ABUSE_MAX_SECONDS\s+(\d+)", source)
    if maximum is None:
        raise AssertionError("production duration cap not found")
    with tempfile.TemporaryDirectory(prefix="redis-durations-") as directory:
        build = pathlib.Path(directory)
        include = build / "redis_record.inc"

        def run(body: str, label: str, width: str) -> subprocess.CompletedProcess:
            include.write_text(body)
            binary = build / label
            command = [
                *shlex.split(os.environ.get("CC", "cc")),
                "-std=c11",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=undefined",
                "-fno-sanitize-recover=all",
                f"-DDURATION_TYPE={width}",
                f"-DMAX_SECONDS={maximum[1]}",
                "-I",
                str(build),
                str(ROOT / "ci/tests/unit/test_redis_durations.c"),
                "-o",
                str(binary),
            ]
            print(shlex.join(command), flush=True)
            subprocess.run(command, check=True)
            info = binary.stat()
            print(
                f"binary={binary} mtime_ns={info.st_mtime_ns} size={info.st_size}",
                flush=True,
            )
            result = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False
            )
            print(result.stdout + result.stderr, end="", flush=True)
            return result

        for width in ("int32_t", "time_t"):
            run(record, f"green-{width}", width).check_returncode()
        if args.negative_controls:
            for field in ("interval", "block", "inactive"):
                widened = f"(int64_t) ctx->zone->{field} * 1000"
                if record.count(widened) != 1:
                    raise AssertionError(f"expected one production widening: {field}")
                mutant = record.replace(widened, f"ctx->zone->{field} * 1000")
                result = run(mutant, f"removed-{field}", "int32_t")
                if (
                    result.returncode == 0
                    or "signed integer overflow" not in result.stderr
                ):
                    raise AssertionError(f"removed {field} widening did not trip UBSan")
                print(f"OK: removed-{field} widening observed red", flush=True)
            run(record, "restored-int32_t", "int32_t").check_returncode()


if __name__ == "__main__":
    main()
