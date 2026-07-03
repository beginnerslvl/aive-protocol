from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

from aive.cli import main as cli_main
from aive.diff import (
    build_diff_payload,
    compute_diff,
    finding_fingerprint,
)
from aive.engine import build_scan_payload


def _write(root: Path, name: str, body: str) -> None:
    (root / name).write_text(body, encoding="utf-8")


def _finding(rule_id: str, file_path: str, line: int, snippet: str, severity: str = "high", confidence: float = 0.9) -> dict:
    return {
        "rule_id": rule_id,
        "title": rule_id,
        "file_path": file_path,
        "line": line,
        "severity": severity,
        "confidence": confidence,
        "snippet": snippet,
        "blast_radius": "localized",
        "exploit_hypothesis": "x",
    }


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_ignores_line_number(self) -> None:
        a = _finding("AIVE-PY-003", "deploy.py", 7, "os.system(cmd)")  # aive: ignore
        b = _finding("AIVE-PY-003", "deploy.py", 42, "os.system(cmd)")  # aive: ignore
        self.assertEqual(finding_fingerprint(a), finding_fingerprint(b))

    def test_fingerprint_ignores_reindentation(self) -> None:
        a = _finding("AIVE-PY-003", "deploy.py", 7, "os.system(cmd)")  # aive: ignore
        b = _finding("AIVE-PY-003", "deploy.py", 7, "    os.system(cmd)")  # aive: ignore
        self.assertEqual(finding_fingerprint(a), finding_fingerprint(b))

    def test_fingerprint_differs_by_file(self) -> None:
        a = _finding("AIVE-PY-003", "deploy.py", 7, "os.system(cmd)")  # aive: ignore
        b = _finding("AIVE-PY-003", "run.py", 7, "os.system(cmd)")  # aive: ignore
        self.assertNotEqual(finding_fingerprint(a), finding_fingerprint(b))


class ComputeDiffTests(unittest.TestCase):
    def test_new_finding_detected(self) -> None:
        baseline = [_finding("AIVE-PY-003", "a.py", 1, "os.system(cmd)")]  # aive: ignore
        current = [
            _finding("AIVE-PY-003", "a.py", 1, "os.system(cmd)"),  # aive: ignore
            _finding("AIVE-PY-001", "b.py", 3, "eval(x)"),  # aive: ignore
        ]
        buckets = compute_diff(current, baseline)
        self.assertEqual(len(buckets["new"]), 1)
        self.assertEqual(buckets["new"][0]["rule_id"], "AIVE-PY-001")
        self.assertEqual(len(buckets["unchanged"]), 1)
        self.assertEqual(len(buckets["fixed"]), 0)

    def test_fixed_finding_detected(self) -> None:
        baseline = [
            _finding("AIVE-PY-003", "a.py", 1, "os.system(cmd)"),  # aive: ignore
            _finding("AIVE-PY-001", "b.py", 3, "eval(x)"),  # aive: ignore
        ]
        current = [_finding("AIVE-PY-003", "a.py", 1, "os.system(cmd)")]  # aive: ignore
        buckets = compute_diff(current, baseline)
        self.assertEqual(len(buckets["fixed"]), 1)
        self.assertEqual(buckets["fixed"][0]["rule_id"], "AIVE-PY-001")

    def test_line_drift_is_not_a_regression(self) -> None:
        baseline = [_finding("AIVE-PY-003", "a.py", 5, "os.system(cmd)")]  # aive: ignore
        current = [_finding("AIVE-PY-003", "a.py", 50, "os.system(cmd)")]  # aive: ignore
        buckets = compute_diff(current, baseline)
        self.assertEqual(buckets["new"], [])
        self.assertEqual(buckets["fixed"], [])
        self.assertEqual(len(buckets["unchanged"]), 1)

    def test_multiplicity_is_respected(self) -> None:
        baseline = [_finding("AIVE-PY-003", "a.py", 1, "os.system(cmd)")]  # aive: ignore
        current = [
            _finding("AIVE-PY-003", "a.py", 1, "os.system(cmd)"),  # aive: ignore
            _finding("AIVE-PY-003", "a.py", 9, "os.system(cmd)"),  # aive: ignore
        ]
        buckets = compute_diff(current, baseline)
        self.assertEqual(len(buckets["new"]), 1)
        self.assertEqual(len(buckets["unchanged"]), 1)


class DiffPayloadTests(unittest.TestCase):
    def test_payload_summary_counts(self) -> None:
        baseline_payload = {
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "findings": [_finding("AIVE-PY-003", "a.py", 1, "os.system(cmd)")],  # aive: ignore
        }
        current = [_finding("AIVE-PY-001", "b.py", 3, "eval(x)")]  # aive: ignore
        payload = build_diff_payload("demo", current, baseline_payload)
        self.assertEqual(payload["schema"], "aive.diff.v1")
        self.assertEqual(payload["summary"]["new"], 1)
        self.assertEqual(payload["summary"]["fixed"], 1)
        self.assertEqual(payload["summary"]["unchanged"], 0)
        self.assertEqual(payload["summary"]["baseline_total"], 1)
        self.assertEqual(payload["summary"]["current_total"], 1)


class DiffCliTests(unittest.TestCase):
    def test_diff_fail_on_new_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # Baseline: repo is clean.
            baseline = root / "baseline.json"
            _write(root, "clean.py", "print('ok')\n")
            baseline.write_text(json.dumps(build_scan_payload(root)), encoding="utf-8")
            # Now introduce a regression and diff against the clean baseline.
            _write(root, "danger.py", "os.system(cmd)\n")  # aive: ignore
            code = cli_main(["diff", str(root), "--baseline", str(baseline), "--fail-on-new"])
        self.assertEqual(code, 1)

    def test_diff_passes_when_no_new_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write(root, "danger.py", "os.system(cmd)\n")  # aive: ignore
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps(build_scan_payload(root)), encoding="utf-8")
            # Same tree, same finding -> no new risk introduced.
            code = cli_main(["diff", str(root), "--baseline", str(baseline), "--fail-on-new"])
        self.assertEqual(code, 0)

    def test_diff_markdown_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            baseline = root / "baseline.json"
            _write(root, "clean.py", "print('ok')\n")
            baseline.write_text(json.dumps(build_scan_payload(root)), encoding="utf-8")
            _write(root, "danger.py", "os.system(cmd)\n")  # aive: ignore
            out = root / "report.md"
            code = cli_main(
                ["diff", str(root), "--baseline", str(baseline), "--markdown", "--output", str(out)]
            )
            report = out.read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertIn("Baseline Drift Report", report)
        self.assertIn("REGRESSION", report)


if __name__ == "__main__":
    unittest.main()
