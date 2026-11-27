#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production Redis lifecycle functions with real hiredis/TCP.

The C fixture counts only nginx event/connection boundary calls. Hiredis owns
the actual async connect, failure, callbacks, descriptor close and context free.
"""

import argparse
import hashlib
import os
import pathlib
import shlex
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_DEPENDENCIES = (
    "ngx_http_error_abuse_redis_check_script",
    "ngx_http_error_abuse_redis_record_script",
)


def require_script_dependencies(functions, template):
    for symbol in SCRIPT_DEPENDENCIES:
        if symbol in functions and template.count(symbol) != 1:
            raise AssertionError(f"fixture must define production dependency: {symbol}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--negative-controls", action="store_true")
    args = parser.parse_args()
    source = (ROOT / "src/ngx_http_error_abuse_module.c").read_text()
    functions = []
    for name in ("cleanup", "connect_callback", "disconnect_callback", "arm_reconnect"):
        start = source.index(f"\nngx_http_error_abuse_redis_{name}(")
        start = source.rindex("\nstatic ", 0, start) + 1
        functions.append(source[start : source.index("\n}\n", start) + 3])
    body = "\n".join(functions)
    template = (ROOT / "ci/tests/unit/test_redis_initial.c.in").read_text()
    require_script_dependencies(body, template)
    with tempfile.TemporaryDirectory(prefix="redis-initial-") as directory:
        build = pathlib.Path(directory)

        def run(functions, label):
            generated = build / f"{label}.c"
            generated.write_text(template.replace("/* REDIS_LIFECYCLE */", functions))
            binary = build / label
            command = [
                *shlex.split(os.environ.get("CC", "cc")),
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-parameter",
                "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all",
                str(generated),
                "-lhiredis",
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
            result = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False, timeout=10
            )
            print(result.stdout + result.stderr, end="", flush=True)
            return result

        run(body, "green").check_returncode()
        if args.negative_controls:
            missing_check_script = template.replace(
                'static const char ngx_http_error_abuse_redis_check_script[] = "return 1";\n',
                "",
            )
            try:
                require_script_dependencies(body, missing_check_script)
            except AssertionError as error:
                expected = (
                    "fixture must define production dependency: "
                    "ngx_http_error_abuse_redis_check_script"
                )
                if str(error) != expected:
                    raise
                print("OK: check-script-dependency observed red", flush=True)
            else:
                raise AssertionError("missing check-script dependency was accepted")

            controls = (
                (
                    "initial-reconnect",
                    "worker->context = NULL;\n        ngx_http_error_abuse_redis_arm_reconnect();",
                    "(void) worker;",
                    "initial failure retained freed context",
                ),
                (
                    "cleanup-detach",
                    "ngx_free_connection(c);",
                    "(void) ngx_free_connection;",
                    "adapter connection was not released exactly once",
                ),
                (
                    "cleanup-timer",
                    "ngx_del_timer(&ev->timeout);",
                    "(void) ev;",
                    "adapter timeout survived context cleanup",
                ),
            )
            for label, original, replacement, failure in controls:
                if body.count(original) != 1:
                    raise AssertionError(f"expected one production mutation: {label}")
                result = run(body.replace(original, replacement), label)
                if (
                    result.returncode != 1
                    or result.stderr.strip() != f"FAIL: {failure}"
                ):
                    raise AssertionError(f"{label} did not fail its lifecycle oracle")
                print(f"OK: {label} observed red", flush=True)
            run(body, "restored").check_returncode()


if __name__ == "__main__":
    main()
