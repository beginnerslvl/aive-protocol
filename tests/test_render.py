from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

from aive.cli import main as cli_main
from aive.engine import build_scan_payload
from aive.render import (
    FORMAT_CHOICES,
    render_compact,
    render_json,
    render_plain,
    render_scan,
)


def _payload_with_findings() -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "vuln.py").write_text(
            "value = eval(user_input)\nos.system(cmd)\n",  # aive: ignore
            encoding="utf-8",
        )
        return build_scan_payload(root)


class RenderTests(unittest.TestCase):
    def test_all_choices_have_a_renderer(self) -> None:
        payload = _payload_with_findings()
        for fmt in FORMAT_CHOICES:
            self.assertTrue(render_scan(payload, fmt))

    def test_json_is_byte_for_byte_default(self) -> None:
        payload = _payload_with_findings()
        self.assertEqual(render_json(payload), json.dumps(payload, indent=2))
        self.assertEqual(render_scan(payload), render_json(payload))

    def test_unknown_format_falls_back_to_json(self) -> None:
        payload = _payload_with_findings()
        self.assertEqual(render_scan(payload, "nope"), render_json(payload))

    def test_compact_is_one_line_per_finding(self) -> None:
        payload = _payload_with_findings()
        lines = render_compact(payload).splitlines()
        self.assertEqual(len(lines), payload["finding_count"])
        self.assertIn("AIVE-PY-001", lines[0])

    def test_compact_marks_clean_repo(self) -> None:
        self.assertIn("clean", render_compact({"repo": "demo", "findings": []}))

    def test_plain_groups_by_severity(self) -> None:
        payload = _payload_with_findings()
        report = render_plain(payload)
        self.assertIn("AIVE Scan Report", report)
        self.assertIn("--- HIGH ---", report)

    def test_plain_handles_empty(self) -> None:
        report = render_plain({"repo": "demo", "findings": [], "finding_count": 0})
        self.assertIn("No findings", report)


class CliFormatTests(unittest.TestCase):
    def test_scan_format_compact_via_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            out = root / "out.txt"
            (root / "danger.py").write_text("os.system(cmd)\n", encoding="utf-8")  # aive: ignore
            code = cli_main(["scan", str(root), "--format", "compact", "--output", str(out)])
            body = out.read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertIn("AIVE-PY-003", body)

    def test_format_composes_with_fail_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            out = root / "out.txt"
            (root / "danger.py").write_text("os.system(cmd)\n", encoding="utf-8")  # aive: ignore
            code = cli_main(
                ["scan", str(root), "--format", "plain", "--output", str(out), "--fail-on", "high"]
            )
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
