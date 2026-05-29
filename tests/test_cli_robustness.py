"""Robustness tests for the AIVE CLI: bad input, non-TTY output, colour policy.

These cover the edge cases a well-behaved command-line tool must survive:
missing/invalid/malformed inputs (clear stderr, non-zero exit -- no traceback),
piped/non-interactive output (no colour by default), the ``--no-color`` and
``NO_COLOR`` / ``FORCE_COLOR`` escape hatches, and terminal-width fallback.
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from aive._terminal import Palette, should_use_color, terminal_width
from aive.cli import main as cli_main


class _FakeTTY(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:  # noqa: D401 - trivial override
        return self._tty


def _write(root: Path, name: str, body: str) -> None:
    (root / name).write_text(body, encoding="utf-8")


class BadInputTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_plan_missing_file_is_clean_error(self) -> None:
        code, out, err = self._run(["plan", "/definitely/missing.json"])
        self.assertEqual(code, 2)
        self.assertIn("not found", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(out, "")

    def test_plan_invalid_json_is_clean_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json{", encoding="utf-8")
            code, _out, err = self._run(["plan", str(bad)])
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)
        self.assertNotIn("Traceback", err)

    def test_plan_malformed_payload_is_clean_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mal = Path(tmp) / "mal.json"
            mal.write_text(json.dumps({"findings": [{"foo": 1}]}), encoding="utf-8")
            code, _out, err = self._run(["plan", str(mal)])
        self.assertEqual(code, 2)
        self.assertIn("not a valid scan payload", err)
        self.assertNotIn("Traceback", err)

    def test_plan_json_array_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            arr = Path(tmp) / "arr.json"
            arr.write_text("[1, 2, 3]", encoding="utf-8")
            code, _out, err = self._run(["plan", str(arr)])
        self.assertEqual(code, 2)
        self.assertIn("JSON object", err)

    def test_scan_missing_target_is_clean_error(self) -> None:
        code, out, err = self._run(["scan", "/no/such/dir"])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)
        self.assertEqual(out, "")

    def test_scan_file_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "a.py"
            f.write_text("print('hi')\n", encoding="utf-8")
            code, _out, err = self._run(["scan", str(f)])
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def test_min_confidence_out_of_range_is_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stderr(io.StringIO()):
                cli_main(["scan", ".", "--min-confidence", "5"])
        self.assertEqual(ctx.exception.code, 2)

    def test_output_to_unwritable_path_is_clean_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "a.py", "print('hi')\n")
            # A file used as if it were a parent directory: cannot mkdir under it.
            blocker = root / "blocker"
            blocker.write_text("x", encoding="utf-8")
            bad_out = blocker / "sub" / "findings.json"
            code, _out, err = self._run(["scan", str(root), "--output", str(bad_out)])
        self.assertEqual(code, 2)
        self.assertIn("could not write output", err)
        self.assertNotIn("Traceback", err)


class ColorPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {k: os.environ.get(k) for k in ("NO_COLOR", "FORCE_COLOR")}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_no_color_when_not_a_tty(self) -> None:
        self.assertFalse(should_use_color(_FakeTTY(False)))

    def test_color_on_tty(self) -> None:
        self.assertTrue(should_use_color(_FakeTTY(True)))

    def test_no_color_flag_overrides_tty(self) -> None:
        self.assertFalse(should_use_color(_FakeTTY(True), no_color=True))

    def test_no_color_env_disables(self) -> None:
        os.environ["NO_COLOR"] = "1"
        self.assertFalse(should_use_color(_FakeTTY(True)))

    def test_force_color_overrides_pipe(self) -> None:
        os.environ["FORCE_COLOR"] = "1"
        self.assertTrue(should_use_color(_FakeTTY(False)))

    def test_verify_output_has_no_ansi_when_piped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, ".gitignore", "x\n")
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli_main(["verify", str(root)])
        self.assertEqual(code, 0)
        self.assertNotIn("\033[", out.getvalue())

    def test_palette_disabled_is_passthrough(self) -> None:
        p = Palette(enabled=False)
        self.assertEqual(p.status("pass"), "pass")
        self.assertEqual(p.paint("x", "red"), "x")

    def test_palette_enabled_wraps_status(self) -> None:
        p = Palette(enabled=True)
        self.assertIn("\033[", p.status("fail"))


class TerminalWidthTests(unittest.TestCase):
    def test_columns_env_honoured(self) -> None:
        saved = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "132"
        try:
            self.assertEqual(terminal_width(), 132)
        finally:
            if saved is None:
                os.environ.pop("COLUMNS", None)
            else:
                os.environ["COLUMNS"] = saved

    def test_fallback_is_reasonable(self) -> None:
        self.assertGreaterEqual(terminal_width(io.StringIO(), default=80), 20)


if __name__ == "__main__":
    unittest.main()
