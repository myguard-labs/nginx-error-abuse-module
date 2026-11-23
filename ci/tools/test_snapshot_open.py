#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Compile the production snapshot opener and test real filesystem objects.

Run in disposable Docker. No device nodes are created: /dev/null supplies the
narrow character-device rejection control. --negative-controls rebuilds with
the regular-file guard removed and requires the device assertion to fail.
"""

import argparse
import os
import pathlib
import shlex
import socket
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--negative-controls", action="store_true")
    args = parser.parse_args()
    source = (ROOT / "src/ngx_http_error_abuse_module.c").read_text()
    start = source.index("static ngx_fd_t\nngx_http_error_abuse_open_snapshot(")
    opener = source[start : source.index("\n}\n", start) + 3]
    template = (ROOT / "ci/tests/unit/test_snapshot_open.c").read_text()
    begin = "/* SNAPSHOT_OPEN_BEGIN */"
    end = "/* SNAPSHOT_OPEN_END */"
    if template.count(begin) != 1 or template.count(end) != 1:
        raise AssertionError("expected one production opener replacement region")
    prefix, region = template.split(begin)
    _, suffix = region.split(end)
    with tempfile.TemporaryDirectory(prefix="snapshot-open-") as directory:
        build = pathlib.Path(directory)
        generated = build / "snapshot_open.c"
        regular = build / "regular"
        regular.write_bytes(struct.pack("<8sIIII", b"NGEAB01", 3, 3, 0, 0))
        (build / "empty").touch()
        (build / "directory").mkdir()
        os.mkfifo(build / "fifo")
        (build / "symlink").symlink_to(regular)
        (build / "symlink-fifo").symlink_to(build / "fifo")

        def compile_opener(body: str, label: str, *flags: str) -> pathlib.Path:
            generated.write_text(prefix + body + suffix)
            binary = build / label
            command = [
                *shlex.split(os.environ.get("CC", "cc")),
                "-std=c11",
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                *flags,
                str(generated),
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
            return binary

        def run(binary: pathlib.Path, name: str, path: pathlib.Path):
            command = [str(binary), name, str(path)]
            print(shlex.join(command), flush=True)
            try:
                result = subprocess.run(
                    command, capture_output=True, text=True, timeout=3, check=False
                )
            except subprocess.TimeoutExpired as exc:
                raise AssertionError(f"{name}: snapshot open blocked") from exc
            print(result.stdout + result.stderr, end="", flush=True)
            return result

        binary = compile_opener(opener, "green")
        with socket.socket(socket.AF_UNIX) as peer:
            peer.bind(str(build / "socket"))
            for name in (
                "regular",
                "empty",
                "fifo",
                "directory",
                "socket",
                "symlink",
                "symlink-fifo",
                "missing",
            ):
                run(binary, name, build / name).check_returncode()
            run(binary, "device", pathlib.Path("/dev/null")).check_returncode()
            run(binary, "fstat-error", regular).check_returncode()
            run(binary, "open-error", regular / "child").check_returncode()

        # Prove both compile-time fallbacks avoid opening even a regular file.
        # These external boundaries are intentionally unused in that branch.
        for flag in ("NONBLOCK", "NOFOLLOW"):
            fallback = compile_opener(
                opener,
                f"missing-{flag}",
                f"-DTEST_NO_{flag}",
                "-Wno-unused-function",
            )
            run(fallback, "unsupported", regular).check_returncode()

        if args.negative_controls:
            guard = "if (!ngx_is_file(fi))"
            if opener.count(guard) != 1:
                raise AssertionError("expected exactly one regular-file guard")
            mutant = compile_opener(opener.replace(guard, "if (0)"), "removed-guard")
            result = run(mutant, "device", pathlib.Path("/dev/null"))
            if result.returncode != 1 or result.stderr.strip() != (
                "FAIL: device: nonregular snapshot accepted"
            ):
                raise AssertionError("removed regular-file guard did not fail")
            print("OK: removed regular-file guard observed red", flush=True)
            restored = compile_opener(opener, "restored")
            run(restored, "device", pathlib.Path("/dev/null")).check_returncode()
            run(restored, "regular", regular).check_returncode()


if __name__ == "__main__":
    main()
