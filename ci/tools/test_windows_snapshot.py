#!/usr/bin/env python3
"""Execute the Windows workflow's snapshot precondition without starting nginx."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]


class SnapshotPrecondition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pwsh = shutil.which("pwsh")
        if cls.pwsh is None:
            raise RuntimeError("snapshot controls require PowerShell: install pwsh")
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/windows-msvc.yml").read_text()
        )
        cls.script = next(
            step["run"]
            for step in workflow["jobs"]["msvc"]["steps"]
            if step.get("name") == "Test persistence and singleton ownership"
        )
        cls.poll_start = cls.script.index("foreach ($i in 1..40)")
        cls.owner_start = cls.script.index("$owners =", cls.poll_start)
        cls.guard = cls.script[cls.poll_start : cls.owner_start]

    def test_guard_precedes_ownership_and_shutdown_inside_try(self):
        start = self.script.index("$proc = Start-Nginx")
        self.assertLess(start, self.script.rindex("try {", start, self.poll_start))
        self.assertLess(
            self.owner_start,
            self.script.index("} finally { Stop-Nginx $proc }", self.poll_start),
        )

    def run_snapshot(self, size):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = pathlib.Path(directory) / "abuse.state"
            if size is not None:
                snapshot.write_bytes(bytes(size))
            script = pathlib.Path(directory) / "snapshot-control.ps1"
            # Sleep is the only mocked command in the extracted polling block.
            # Shutdown always writes a populated snapshot: checking only after
            # cleanup would therefore accept every fixture, including missing.
            script.write_text(
                "$ErrorActionPreference = 'Stop'\n"
                "$snapshot = $env:EA_TEST_SNAPSHOT\n"
                "function Start-Sleep { }\n"
                "try {\n" + self.guard + "Write-Output 'snapshot-accepted'\n"
                "} catch {\n"
                "Write-Output ('snapshot-rejected: ' + $_.Exception.Message)\n"
                "exit 9\n"
                "} finally {\n"
                "[IO.File]::WriteAllBytes($snapshot, [byte[]]::new(25))\n"
                "Write-Output 'shutdown-populated'\n"
                "}\n"
            )
            result = subprocess.run(
                [
                    self.pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(script),
                ],
                env=os.environ | {"EA_TEST_SNAPSHOT": str(snapshot)},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(snapshot.stat().st_size, 25, result.stderr)
            self.assertIn("shutdown-populated", result.stdout, result.stderr)
            return result

    def test_missing_and_header_only_rejected_before_shutdown(self):
        for size in (None, 0, 1, 23, 24):
            with self.subTest(snapshot_bytes=size):
                result = self.run_snapshot(size)
                self.assertEqual(
                    result.returncode, 9, "invalid snapshot accepted: " + result.stdout
                )
                self.assertIn(
                    "snapshot-rejected: populated snapshot was not written",
                    result.stdout,
                )
                self.assertNotIn("snapshot-accepted", result.stdout)
                self.assertLess(
                    result.stdout.index("snapshot-rejected:"),
                    result.stdout.index("shutdown-populated"),
                )

    def test_populated_snapshot_continues_before_shutdown(self):
        result = self.run_snapshot(25)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("snapshot-rejected:", result.stdout)
        self.assertLess(
            result.stdout.index("snapshot-accepted"),
            result.stdout.index("shutdown-populated"),
        )


if __name__ == "__main__":
    unittest.main()
