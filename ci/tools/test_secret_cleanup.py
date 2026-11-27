#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Test production secret helpers with real nginx pools and a removed-wipe control.

--core is a configured nginx/Angie source tree. Both pool allocation modes run:
small blocks and NGX_DEBUG_PALLOC's separate large allocations. This unit checks
bytes before free; runtime configuration/reload compatibility lives separately
in test_runtime.py --secret-lifetime-only.
"""

import argparse
import hashlib
import os
import pathlib
import shlex
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=pathlib.Path, required=True)
    parser.add_argument("--negative-controls", action="store_true")
    args = parser.parse_args()
    core = args.core.resolve()
    source = (ROOT / "src/ngx_http_error_abuse_module.c").read_text()
    helpers = []
    for name in ("secret_cleanup", "secret_alloc"):
        start = source.index(f"\nngx_http_error_abuse_{name}(")
        start = source.rindex("\nstatic ", 0, start) + 1
        helpers.append(source[start : source.index("\n}\n", start) + 3])
    body = "\n".join(helpers)
    # Pin both consumers, including their NULL checks, to the tested owner.
    for target, length in (
        ("zone->persist_secret.data", "keylen"),
        ("mcf->redis.password.data", "password.len"),
    ):
        expected = (
            f"{target} = ngx_http_error_abuse_secret_alloc(cf->pool, {length}); "
            f"if ({target} == NULL) {{ return NGX_CONF_ERROR; }}"
        )
        if expected not in " ".join(source.split()):
            raise AssertionError(f"secret consumer lost tested allocation: {target}")
    template = (ROOT / "ci/tests/unit/test_secret_cleanup.c.in").read_text()
    with tempfile.TemporaryDirectory(prefix="secret-cleanup-") as directory:
        build = pathlib.Path(directory)

        def run(helpers, label, debug):
            generated = build / f"{label}.c"
            generated.write_text(template.replace("/* SECRET_HELPERS */", helpers))
            binary = build / label
            command = [
                *shlex.split(os.environ.get("CC", "cc")),
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all",
                "-ffunction-sections",
                "-fdata-sections",
                "-Wl,--gc-sections",
                f"-DNGX_DEBUG_PALLOC={debug}",
                *[
                    f"-I{core / p}"
                    for p in ("src/core", "src/event", "src/os/unix", "objs")
                ],
                str(generated),
                str(core / "src/core/ngx_palloc.c"),
                str(core / "src/core/ngx_string.c"),
                str(core / "src/os/unix/ngx_alloc.c"),
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
                [str(binary)], capture_output=True, text=True, check=False
            )
            print(result.stdout + result.stderr, end="", flush=True)
            return result

        for debug in (0, 1):
            run(body, f"green-{debug}", debug).check_returncode()
            if args.negative_controls:
                wipe = "ngx_explicit_memzero(secret->data, secret->len);"
                if body.count(wipe) != 1:
                    raise AssertionError("expected one production wipe")
                mutant = body.replace(wipe, "(void) secret;")
                result = run(mutant, f"removed-wipe-{debug}", debug)
                if result.returncode != 1 or result.stderr.strip() != (
                    "FAIL: owned secret was not wiped before pool free"
                ):
                    raise AssertionError("removed wipe did not fail its byte oracle")
                print("OK: removed wipe observed red", flush=True)
                run(body, f"restored-{debug}", debug).check_returncode()


if __name__ == "__main__":
    main()
