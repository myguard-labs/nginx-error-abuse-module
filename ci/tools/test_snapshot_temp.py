#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Compile production snapshot writer; prove lease/cleanup on real files.

Run in disposable Docker. A writer paused immediately after temp creation is
killed by this test to model interruption. Mutants must fail named assertions.
"""

import argparse
import hashlib
import os
import pathlib
import selectors
import shlex
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAGIC = b"NGEAB-TEMP-v1\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--negative-controls", action="store_true")
    args = parser.parse_args()
    source = (ROOT / "src/ngx_http_error_abuse_module.c").read_text()

    def function(name):
        start = source.index("\n" + name + "(")
        start = source.rindex("\nstatic ", 0, start) + 1
        return source[start : source.index("\n}\n", start) + 3]

    helpers = "\n".join(
        function("ngx_http_error_abuse_" + name)
        for name in (
            "platform_interrupted",
            "platform_create_temp",
            "platform_flush_file",
            "platform_replace",
            "write_all",
            "platform_sync_parent",
            "temp_lease",
            "prepare_temp",
        )
    )
    writer = function("ngx_http_error_abuse_write_file").replace(
        "ngx_http_error_abuse_platform_create_temp(tmp, log)",
        "paused_create(tmp, log)",
    )
    template = (ROOT / "ci/tests/unit/test_snapshot_temp.c.in").read_text()
    with tempfile.TemporaryDirectory(prefix="snapshot-temp-") as directory:
        build = pathlib.Path(directory)

        def compile_body(body, label):
            generated = build / (label + ".c")
            generated.write_text(
                template.replace("/* PRODUCTION_HELPERS */", body).replace(
                    "/* PRODUCTION_WRITER */", writer
                )
            )
            binary = build / label
            command = [
                *shlex.split(os.environ.get("CC", "cc")),
                "-std=c11",
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-parameter",
                "-Wno-unused-function",
                str(generated),
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

        def run(binary, path, **env):
            command = [str(binary), str(path)]
            print(shlex.join(command), flush=True)
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=5,
                check=False,
                env={**os.environ, **env},
            )
            print(f"exit={result.returncode}", flush=True)
            return result.returncode

        def initial_race(binary, path):
            command = [str(binary), str(path)]
            print(shlex.join(command) + " EA_PAUSE_INIT=1", flush=True)
            creator = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                env={**os.environ, "EA_PAUSE_INIT": "1"},
            )
            contender = None
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(creator.stdout, selectors.EVENT_READ)
                    assert ready.select(5), "creator did not reach marker creation"
                assert creator.stdout.readline().strip() == "OWNER_CREATED"
                print(shlex.join(command) + " EA_PAUSE_LEASE=1", flush=True)
                contender = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    text=True,
                    env={**os.environ, "EA_PAUSE_LEASE": "1"},
                )
                with selectors.DefaultSelector() as ready:
                    ready.register(contender.stdout, selectors.EVENT_READ)
                    assert ready.select(5), "contender did not settle"
                line = contender.stdout.readline().strip()
                assert line != "LEASED", "initial-race: empty marker lease was acquired"
                assert contender.wait(timeout=5) == 1
                creator.communicate(input="\n", timeout=5)
                assert creator.returncode == 0, (
                    "initial-race: creator failed to publish"
                )
            finally:
                for process in (contender, creator):
                    if process is not None and process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)

        def check(binary, case):
            with tempfile.TemporaryDirectory(dir=build) as directory:
                parent = pathlib.Path(directory)
                path = parent / "state"
                namespace = parent / "state.eab-tmp"
                slot = namespace / "snapshot"
                legacy = parent / "state.tmp.1.deadbeef"
                legacy.write_bytes(b"unrelated legacy")
                path.write_bytes(b"old snapshot")
                if case in ("marker-write-error", "marker-short-error"):
                    failure = "zero" if case == "marker-write-error" else "partial"
                    assert run(binary, path, EA_MARKER_WRITE_FAIL=failure) == 1
                    assert path.read_bytes() == b"old snapshot"
                    assert not namespace.exists(), (
                        "marker-write: owned unpublished namespace survived"
                    )
                    assert run(binary, path) == 0, "marker-write: recovery failed"
                elif case == "initial-race":
                    initial_race(binary, path)
                    assert run(binary, path) == 0, "initial-race: namespace stranded"
                elif case == "same-process":
                    assert run(binary, path) == 0
                    assert run(binary, path, EA_SAME_PROCESS="1") == 0, (
                        "same-process: live lease was stolen"
                    )
                elif case in ("marker-fsync", "data-fsync"):
                    failure = "1" if case == "marker-fsync" else "2"
                    assert run(binary, path, EA_FSYNC_FAIL=failure) == 1, (
                        "fsync error accepted"
                    )
                    assert path.read_bytes() == b"old snapshot", (
                        "fsync failure replaced snapshot"
                    )
                    assert not slot.exists(), "fsync failure stranded slot"
                    assert run(binary, path) == 0, "fsync recovery failed"
                elif case in ("initial", "concurrent", "interrupted"):
                    if case == "initial":
                        assert run(binary, path) == 0, "initial: snapshot rejected"
                    else:
                        command = [str(binary), str(path)]
                        print(shlex.join(command) + " EA_PAUSE=1", flush=True)
                        with subprocess.Popen(
                            command,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            text=True,
                            env={**os.environ, "EA_PAUSE": "1"},
                        ) as proc:
                            try:
                                with selectors.DefaultSelector() as ready:
                                    ready.register(proc.stdout, selectors.EVENT_READ)
                                    assert ready.select(5), (
                                        "writer did not reach temp creation"
                                    )
                                assert proc.stdout.readline().strip() == "CREATED"
                                assert slot.exists()
                                if case == "concurrent":
                                    assert run(binary, path) == 1, (
                                        "concurrent: live lease was stolen"
                                    )
                                    assert slot.exists(), (
                                        "concurrent: live slot removed"
                                    )
                                    assert path.read_bytes() == b"old snapshot"
                            finally:
                                proc.kill()  # owned interruption; never an external stop
                                proc.wait(timeout=5)
                        assert slot.exists(), "interrupted: no stranded slot"
                        assert run(binary, path) == 0, (
                            "interrupted: stale slot was not reclaimed"
                        )
                else:
                    namespace.mkdir(mode=0o700)
                    owner = namespace / "owner"
                    if case not in ("unpublished", "owner-symlink"):
                        contents = {
                            "invalid": b"x" * len(MAGIC),
                            "partial": MAGIC[:-1],
                            "overlong": MAGIC + b"x",
                        }.get(case, MAGIC)
                        owner.write_bytes(contents)
                        owner.chmod(0o600)
                    slot.write_bytes(b"old temporary")
                    unrelated = namespace / "unrelated"
                    unrelated.write_bytes(b"keep")
                    if case == "owner-symlink":
                        owner.symlink_to(legacy)
                    if case == "directory-symlink":
                        saved = parent / "saved"
                        namespace.rename(saved)
                        namespace.symlink_to(saved, target_is_directory=True)
                    if case in (
                        "invalid",
                        "partial",
                        "overlong",
                        "unpublished",
                        "owner-symlink",
                        "directory-symlink",
                    ):
                        assert run(binary, path) == 1, (
                            "ownership: unowned namespace accepted"
                        )
                        assert slot.read_bytes() == b"old temporary", (
                            "ownership: foreign slot removed"
                        )
                        assert path.read_bytes() == b"old snapshot"
                        # Safe operator recovery: move aside, never delete or adopt.
                        namespace.rename(parent / "preserved-namespace")
                        assert run(binary, path) == 0, (
                            "recovery: fresh namespace rejected"
                        )
                    elif case == "slot-directory":
                        slot.unlink()
                        slot.mkdir()
                        assert run(binary, path) == 1, "error: directory slot accepted"
                        assert slot.is_dir()
                    else:
                        assert run(binary, path) == 0, (
                            "interrupted: stale slot was not reclaimed"
                        )
                        assert not slot.exists()
                        assert unrelated.read_bytes() == b"keep"
                assert legacy.read_bytes() == b"unrelated legacy", "legacy file changed"
                if case != "slot-directory":
                    assert path.read_bytes() == b"new snapshot", "new snapshot missing"
                print(f"OK: {case}", flush=True)

        cases = (
            "initial",
            "marker-write-error",
            "marker-short-error",
            "initial-race",
            "same-process",
            "interrupted",
            "concurrent",
            "owned-stale",
            "invalid",
            "partial",
            "overlong",
            "marker-fsync",
            "data-fsync",
            "unpublished",
            "owner-symlink",
            "directory-symlink",
            "slot-directory",
        )
        binary = compile_body(helpers, "green")
        for case in cases:
            check(binary, case)
        if args.negative_controls:
            mutations = (
                (
                    "cleanup",
                    "ngx_delete_file(tmp) == NGX_FILE_ERROR",
                    "0 == NGX_FILE_ERROR",
                    "interrupted",
                    "interrupted: stale slot was not reclaimed",
                ),
                (
                    "lease",
                    "flock(fd, LOCK_EX|LOCK_NB) != 0",
                    "0",
                    "concurrent",
                    "concurrent: live lease was stolen",
                ),
                (
                    "same-process-lock",
                    "flock(fd, LOCK_EX|LOCK_NB) != 0",
                    "test_process_lock(fd) != 0",
                    "same-process",
                    "same-process: live lease was stolen",
                ),
                (
                    "initial-publication",
                    '(!*fresh && fi.st_size != sizeof("NGEAB-TEMP-v1\\n") - 1)',
                    "0",
                    "initial-race",
                    "initial-race: empty marker lease was acquired",
                ),
                (
                    "unpublished-error-cleanup",
                    (
                        "Remove only our exclusive creation; never a published marker. */\n"
                        "            (void) ngx_delete_file(owner);"
                    ),
                    (
                        "Remove only our exclusive creation; never a published marker. */\n"
                        "            (void) 0;"
                    ),
                    "marker-write-error",
                    "marker-write: owned unpublished namespace survived",
                ),
                (
                    "marker",
                    (
                        "n != sizeof(magic) - 1\n"
                        "            || ngx_memcmp(marker, magic, sizeof(magic) - 1) != 0"
                    ),
                    (
                        "0 && (n != sizeof(magic) - 1 || "
                        "ngx_memcmp(marker, magic, sizeof(magic) - 1) != 0)"
                    ),
                    "invalid",
                    "ownership: unowned namespace accepted",
                ),
            )
            for label, old, new, case, message in mutations:
                assert helpers.count(old) == 1, label + ": mutation site changed"
                mutant = compile_body(helpers.replace(old, new), label)
                try:
                    check(mutant, case)
                except AssertionError as error:
                    assert str(error) == message, str(error)
                    print(f"OBSERVED RED: {case}: {error}", flush=True)
                else:
                    raise AssertionError(label + ": mutation survived")
            restored = compile_body(helpers, "restored")
            for case in cases:
                check(restored, case)


if __name__ == "__main__":
    main()
