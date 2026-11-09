"""Regression: decoding errors must survive artifact collection and fail the runner."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bgv_runner", HERE / "run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class FailurePropagation(unittest.TestCase):
    def invoke(self, returncode, wrong, candidate=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            argv = ["run.py", "--exe", sys.executable, "--mode", "stress",
                    "--profile", "FaceNet-3", "--max-enrollments", "64",
                    "--out", str(root / "results"), "--binary-dir", str(root / "binary")]
            if candidate:
                argv += ["--parameter-set", "incremental-candidate"]

            def execute(cmd, **kwargs):
                self.assertEqual(cmd[5], "64")
                if candidate:
                    self.assertEqual(cmd[6], "60,50,50,50")
                dest = Path(cmd[4])
                dest.mkdir(parents=True)
                sample = {"enrollments": 64, "wrong_slots": wrong,
                          "wrong_packed_slots": wrong, "wrong_row_slots": 0,
                          "fresh_wrong_slots": 0, "fresh_wrong_packed_slots": 0}
                (dest / "stress.jsonl").write_text(json.dumps(sample) + "\n")
                return subprocess.CompletedProcess(cmd, returncode)

            with patch.object(sys, "argv", argv), patch.object(runner.subprocess, "run", execute):
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                    runner.main()
            summary = json.loads((root / "results/summary.json").read_text())["profiles"][0]
            self.assertTrue((root / "results/FaceNet-3/stress.jsonl").exists())
            self.assertFalse(summary["completedCapacity"])
            return stopped.exception.code, summary

    def test_decoding_failure_preserves_raw_evidence(self):
        code, result = self.invoke(2, 8192)
        self.assertEqual(code, 2)
        self.assertFalse(result["correctAtAllCheckpoints"])

    def test_legacy_success_exit_does_not_hide_decoding_failure(self):
        code, result = self.invoke(0, 8192)
        self.assertEqual(code, 2)
        self.assertFalse(result["correctAtAllCheckpoints"])

    def test_process_failure_is_not_overridden_by_zero_error_fields(self):
        code, _ = self.invoke(2, 0)
        self.assertEqual(code, 2)

    def test_candidate_pass_is_explicitly_partial(self):
        code, result = self.invoke(0, 0, candidate=True)
        self.assertEqual(code, 0)
        self.assertTrue(result["correctAtAllCheckpoints"])


if __name__ == "__main__":
    unittest.main()
