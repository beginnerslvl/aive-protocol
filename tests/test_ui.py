from __future__ import annotations

import io
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
import unittest

from aive import ui
from aive.cli import main as cli_main
from aive.engine import build_scan_payload, run_verification


def _demo_repo(root: Path) -> None:
    (root / "demo.py").write_text("value = eval(user_input)\n", encoding="utf-8")  # aive: ignore


class PlainFallbackTests(unittest.TestCase):
    """The UI layer must render even when rich is unavailable."""

    def test_plain_scan_render(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _demo_repo(root)
            payload = build_scan_payload(root)
        buf = io.StringIO()
        with redirect_stdout(buf):
            ui.render_scan_payload(None, payload)  # None console => plain path
        out = buf.getvalue()
        self.assertIn("AIVE-PY-001", out)
        self.assertIn("high", out)

    def test_plain_verify_render(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            checks = run_verification(Path(tmpdir))
        buf = io.StringIO()
        with redirect_stdout(buf):
            ui.render_verification(None, [c.to_dict() for c in checks])
        self.assertIn("python-syntax", buf.getvalue())

    def test_scan_with_progress_none_console_returns_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _demo_repo(root)
            payload = ui.scan_with_progress(None, root, 0.0, build_scan_payload)
        self.assertEqual(payload["finding_count"], 1)


class CliPrettyTests(unittest.TestCase):
    """--pretty must not change exit codes or break the command."""

    def test_scan_pretty_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _demo_repo(root)
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_main(["scan", str(root), "--pretty"])
        self.assertEqual(code, 0)

    def test_scan_pretty_still_gates_on_fail_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _demo_repo(root)
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_main(["scan", str(root), "--pretty", "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_verify_pretty_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_main(["verify", str(tmpdir), "--pretty"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
