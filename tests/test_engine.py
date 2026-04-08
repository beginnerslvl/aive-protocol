from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from aive.engine import build_patch_plan_markdown, build_scan_payload, run_verification


class EngineTests(unittest.TestCase):
    def test_scan_payload_detects_dynamic_exec(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "demo.py").write_text("value = eval(user_input)\n", encoding="utf-8")
            payload = build_scan_payload(root)

        self.assertEqual(payload["finding_count"], 1)
        finding = payload["findings"][0]
        self.assertEqual(finding["rule_id"], "AIVE-PY-001")

    def test_patch_plan_mentions_decision_frame(self) -> None:
        payload = {
            "repo": "demo",
            "scanned_at": "2026-04-08T00:00:00+00:00",
            "findings": [],
        }

        markdown = build_patch_plan_markdown(payload)
        self.assertIn("Decision Frame", markdown)
        self.assertIn("No high-signal findings", markdown)

    def test_verification_detects_gitignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
            checks = run_verification(root)

        names = {check.name: check.status for check in checks}
        self.assertEqual(names["repo-hygiene"], "pass")


if __name__ == "__main__":
    unittest.main()
