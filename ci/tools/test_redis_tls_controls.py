#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Focused, socket-free controls for the Redis TLS integration probe."""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_redis_tls as probe


class ProbeControls(unittest.TestCase):
    def test_certificate_rejection_status_is_specific(self):
        for success, status in ((True, 0), (False, 3)):
            probe.check_client_status(
                subprocess.CompletedProcess([], status, stderr=b""), success, "case"
            )
        for status in (-11, -6, 1, 2, 127):
            with (
                self.subTest(status=status),
                self.assertRaisesRegex(AssertionError, "unexpected client status"),
            ):
                probe.check_client_status(
                    subprocess.CompletedProcess([], status, stderr=b""), False, "case"
                )
        with self.assertRaisesRegex(AssertionError, "unexpected client status 3"):
            probe.check_client_status(
                subprocess.CompletedProcess([], 3, stderr=b""), True, "case"
            )

    def test_optimized_execution_stops_before_fixture_creation(self):
        for arguments in ([], ["--nginx-binary", "unused", "--module", "unused"]):
            with (
                self.subTest(arguments=arguments),
                tempfile.TemporaryDirectory() as tmp,
            ):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(pathlib.Path(probe.__file__).resolve()),
                        *arguments,
                    ],
                    env={**os.environ, "PYTHONOPTIMIZE": "1", "TMPDIR": tmp},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("requires Python without optimization", result.stderr)
                self.assertEqual(list(pathlib.Path(tmp).iterdir()), [])

    def test_docker_guard_stops_before_fixture_creation(self):
        with (
            mock.patch.object(
                sys, "argv", ["probe", "--nginx-binary", "unused", "--module", "unused"]
            ),
            mock.patch.object(pathlib.Path, "exists", return_value=False),
            mock.patch.object(probe.tempfile, "TemporaryDirectory") as directory,
            self.assertRaisesRegex(AssertionError, "requires Docker"),
        ):
            probe.main()
        directory.assert_not_called()

    def test_ca_cleanup_covers_setup_and_probe_errors(self):
        for failure in ("write", "rehash", "probe", None):
            with self.subTest(failure=failure):
                self.check_ca_cleanup(failure)

    def check_ca_cleanup(self, failure):
        path_type = pathlib.Path
        with tempfile.TemporaryDirectory() as tmp:
            root = path_type(tmp)
            certs = root / "certs"
            certs.mkdir()
            hosts = root / "hosts"
            hosts.write_bytes(b"127.0.0.1 localhost\n")
            (root / "ca.pem").write_bytes(b"fixture")
            installed = certs / f"redis-tls-{root.name}.pem"
            calls = []

            def mapped_path(value):
                return {"/etc/ssl/certs": certs, "/etc/hosts": hosts}.get(
                    str(value), path_type(value)
                )

            def rehash(*args):
                self.assertEqual(args, ("openssl", "rehash", "/etc/ssl/certs"))
                calls.append(installed.exists())
                if len(calls) == 1 and failure == "rehash":
                    raise OSError("fixture rehash failure")

            original_write = path_type.write_bytes

            def write(path, data):
                result = original_write(path, data)
                if path == installed and failure == "write":
                    raise OSError("fixture write failure")
                return result

            def run_fixture():
                with probe.nginx_fixtures(root) as ca:
                    self.assertEqual(ca.read_bytes(), b"fixture")
                    self.assertIn(b"redis1.example.test", hosts.read_bytes())
                    if failure == "probe":
                        raise OSError("fixture probe failure")

            with (
                mock.patch.object(probe.pathlib, "Path", side_effect=mapped_path),
                mock.patch.object(probe, "command", side_effect=rehash),
                mock.patch.object(path_type, "write_bytes", write),
            ):
                if failure:
                    with self.assertRaisesRegex(OSError, f"fixture {failure} failure"):
                        run_fixture()
                else:
                    run_fixture()
            self.assertFalse(installed.exists())
            self.assertEqual(hosts.read_bytes(), b"127.0.0.1 localhost\n")
            self.assertEqual(calls, [False] if failure == "write" else [True, False])


if __name__ == "__main__":
    unittest.main()
