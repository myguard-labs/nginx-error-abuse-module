#!/usr/bin/env python3
"""Execute the Windows workflow's snapshot precondition without starting nginx."""

import json
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
        threshold = cls.script.index(
            "throw 'requests before the threshold did not return 404'"
        )
        guard_start = cls.script.index("}\n", threshold) + 2
        cls.guard = cls.script[guard_start : cls.owner_start]

    def test_guard_precedes_ownership_and_shutdown_inside_try(self):
        start = self.script.index("$proc = Start-Nginx")
        self.assertLess(start, self.script.rindex("try {", start, self.poll_start))
        self.assertLess(
            self.owner_start,
            self.script.index("} finally { Stop-Nginx $proc }", self.poll_start),
        )

    def run_snapshot(self, observations, lookups, sleeps):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = pathlib.Path(directory) / "abuse.state"
            script = pathlib.Path(directory) / "snapshot-control.ps1"
            # Each sleep advances to the next observation, retaining the last.
            # Real filesystem metadata supplies sizes and missing-file errors.
            # After success, publish the next observation immediately so any
            # redundant metadata read encounters the simulated replacement gap.
            script.write_text(
                "$ErrorActionPreference = 'Stop'\n"
                "$snapshot = $env:EA_TEST_SNAPSHOT\n"
                "$script:observations = @(ConvertFrom-Json $env:EA_TEST_OBSERVATIONS)\n"
                "$script:observation = 0\n"
                "$script:lookups = 0\n"
                "$script:sleeps = 0\n"
                "function Set-Observation {\n"
                "  $value = $script:observations[$script:observation]\n"
                "  if ($null -eq $value) {\n"
                "    [IO.File]::Delete($snapshot)\n"
                "  } elseif ($value -eq 'error') {\n"
                "    [IO.File]::WriteAllBytes($snapshot, [byte[]]::new(25))\n"
                "  } else {\n"
                "    [IO.File]::WriteAllBytes($snapshot, [byte[]]::new($value))\n"
                "  }\n"
                "}\n"
                "function Next-Observation {\n"
                "  if ($script:observation -lt $script:observations.Count - 1) {\n"
                "    $script:observation++\n"
                "    Set-Observation\n"
                "  }\n"
                "}\n"
                "function Start-Sleep {\n"
                "  $script:sleeps++\n"
                "  Next-Observation\n"
                "}\n"
                "function Get-Item {\n"
                "  [CmdletBinding()]\n"
                "  param([Parameter(Position=0)][string]$LiteralPath)\n"
                "  $script:lookups++\n"
                "  if ($LiteralPath -ne $snapshot) { throw 'unexpected metadata path' }\n"
                "  if ($script:observations[$script:observation] -eq 'error') {\n"
                "    throw [IO.IOException]::new('fixture metadata lookup failed')\n"
                "  }\n"
                "  $item = Microsoft.PowerShell.Management\\Get-Item `\n"
                "    -LiteralPath $LiteralPath -ErrorAction Stop\n"
                "  if ($item.Length -gt 24) { Next-Observation }\n"
                "  return $item\n"
                "}\n"
                "Set-Observation\n"
                "try {\n" + self.guard + "Write-Output 'snapshot-accepted'\n"
                "} catch {\n"
                "Write-Output ('snapshot-rejected: ' + $_.Exception.Message)\n"
                "exit 9\n"
                "} finally {\n"
                "Write-Output ('metadata-lookups: ' + $script:lookups)\n"
                "Write-Output ('poll-sleeps: ' + $script:sleeps)\n"
                # Cleanup always populates the snapshot, so accepting only after
                # cleanup would incorrectly accept every rejected fixture.
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
                env=os.environ
                | {
                    "EA_TEST_SNAPSHOT": str(snapshot),
                    "EA_TEST_OBSERVATIONS": json.dumps(observations),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(snapshot.stat().st_size, 25, result.stderr)
            self.assertIn("shutdown-populated", result.stdout, result.stderr)
            self.assertIn(f"metadata-lookups: {lookups}\n", result.stdout)
            self.assertIn(f"poll-sleeps: {sleeps}\n", result.stdout)
            return result

    def assert_rejected(self, observations):
        result = self.run_snapshot(observations, lookups=40, sleeps=40)
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

    def assert_accepted(self, observations, lookups, sleeps):
        result = self.run_snapshot(observations, lookups, sleeps)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("snapshot-rejected:", result.stdout)
        self.assertLess(
            result.stdout.index("snapshot-accepted"),
            result.stdout.index("shutdown-populated"),
        )

    def test_missing_and_header_only_rejected_before_shutdown(self):
        for size in (None, 0, 1, 23, 24):
            with self.subTest(snapshot_bytes=size):
                self.assert_rejected([size])

    def test_populated_snapshot_continues_before_shutdown(self):
        self.assert_accepted([25], lookups=1, sleeps=0)

    def test_missing_then_populated_snapshot(self):
        self.assert_accepted([None, 25], lookups=2, sleeps=1)

    def test_transient_metadata_error_then_populated_snapshot(self):
        self.assert_accepted(["error", 25], lookups=2, sleeps=1)

    def test_header_only_then_populated_snapshot(self):
        self.assert_accepted([24, 25], lookups=2, sleeps=1)

    def test_persistent_metadata_error_rejected_before_shutdown(self):
        self.assert_rejected(["error"])

    def test_success_then_disappearance_is_not_rechecked(self):
        self.assert_accepted([25, None], lookups=1, sleeps=0)

    def test_success_then_lookup_error_is_not_rechecked(self):
        self.assert_accepted([25, "error"], lookups=1, sleeps=0)


if __name__ == "__main__":
    unittest.main()
