"""Controls for minimized corpus publication paths."""

import unittest
from pathlib import Path
from unittest import mock

import yaml

from ci.tools import test_ci_fuzz as fixture

fuzz = fixture.fuzz


class FuzzNamespaceTests(unittest.TestCase):
    def setUp(self):
        fixture.FuzzTests.setUp(self)

    def test_minimization_namespace_avoids_discovered_corpus_collisions(self):
        (self.root / "fuzz_accept-min.c").touch()
        (self.root / "fuzz_accept-min").touch()
        (self.root / "corpus_accept-min").mkdir()
        selected = fuzz.targets(self.root)
        inputs = {name: corpus for name, (_, corpus, _) in selected.items()}
        for name, corpus in inputs.items():
            (corpus / "seed").write_bytes(name.encode())
        before = {
            name: (corpus / "seed").read_bytes() for name, corpus in inputs.items()
        }

        def execute(args, **_kwargs):
            if "-merge=1" in args:
                (Path(args[2]) / "output").write_bytes(Path(args[3]).name.encode())
                control = Path(
                    next(
                        a.split("=", 1)[1]
                        for a in args
                        if a.startswith("-merge_control_file=")
                    )
                )
                seed = Path(args[3]) / "seed"
                control.write_text(
                    f"1\n0\n{seed}\nSTARTED 0 {seed.stat().st_size}\nFT 0\n",
                    encoding="utf-8",
                )

        with mock.patch.object(fuzz.subprocess, "run", side_effect=execute):
            fuzz.run(self.root, "120", True)
        outputs = {
            name: self.root / "minimized" / corpus.name
            for name, corpus in inputs.items()
        }
        self.assertTrue(set(outputs.values()).isdisjoint(inputs.values()))
        self.assertEqual(len(set(outputs.values())), len(inputs))
        for name, corpus in inputs.items():
            self.assertEqual((corpus / "seed").read_bytes(), before[name])
            self.assertEqual(
                (outputs[name] / "output").read_bytes(), corpus.name.encode()
            )

        previous = outputs["accept"] / "output"
        original_rename = Path.rename

        def deny(path, destination):
            if destination == outputs["accept"]:
                raise PermissionError("publication and rollback denied")
            return original_rename(path, destination)

        with (
            mock.patch.object(fuzz.subprocess, "run", side_effect=execute),
            mock.patch.object(Path, "rename", new=deny),
            self.assertRaisesRegex(PermissionError, "publication and rollback denied"),
        ):
            fuzz.minimize(selected["accept"][0], inputs["accept"], self.root)
        recovery = list(self.root.glob(".corpus_accept-*/previous/output"))
        self.assertEqual(len(recovery), 1)
        self.assertEqual(recovery[0].read_bytes(), b"corpus_accept")
        for name, corpus in inputs.items():
            self.assertEqual((corpus / "seed").read_bytes(), before[name])
        self.assertFalse(previous.exists())

    def test_success_upload_only_selects_minimized_outputs(self):
        workflow = yaml.safe_load(
            (
                Path(__file__).resolve().parents[2] / ".github/workflows/ci-deep.yml"
            ).read_text()
        )
        steps = workflow["jobs"]["fuzz"]["steps"]
        upload = next(
            step for step in steps if step.get("name") == "Upload minimized corpus"
        )
        self.assertEqual(upload["if"], "success()")
        self.assertEqual(
            upload["with"]["path"], "${{ github.workspace }}/ci/fuzz/minimized/"
        )
