"""Tests for the ``aive`` CLI dispatch layer (``aive.cli``).

Exercises the three subcommands through ``main()`` in-process: argument
parsing, exit codes, stdout rendering, and ``--output`` file writing.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aive.cli import build_parser, main


# --------------------------------------------------------------------------- #
# argument parsing / --version
# --------------------------------------------------------------------------- #
def test_missing_subcommand_errors() -> None:
    with pytest.raises(SystemExit):
        main([])


def test_version_flag_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "aive" in capsys.readouterr().out


def test_build_parser_registers_all_subcommands() -> None:
    parser = build_parser()
    # argparse stores choices for the subparser action.
    sub = next(a for a in parser._actions if getattr(a, "choices", None) and "scan" in a.choices)
    # The core loop stages are always present; optional UX subcommands (e.g. the
    # rich `tui`) and later feature additions register alongside them.
    assert {"scan", "plan", "verify"}.issubset(set(sub.choices))


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def test_scan_prints_json_to_stdout(sample_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", str(sample_repo)])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "aive.scan.v1"
    assert payload["finding_count"] >= 3


def test_scan_writes_output_file(sample_repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "nested" / "findings.json"
    code = main(["scan", str(sample_repo), "--output", str(out)])
    assert code == 0
    assert out.exists()  # parent dir auto-created
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["finding_count"] >= 3


def test_scan_min_confidence_drops_low_signal(sample_repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "f.json"
    main(["scan", str(sample_repo), "--min-confidence", "0.9", "--output", str(out)])
    payload = json.loads(out.read_text(encoding="utf-8"))
    # Only the >=0.9 dynamic-exec finding survives.
    assert payload["severity_summary"]["low"] == 0
    assert payload["severity_summary"]["medium"] == 0


def test_scan_fail_on_high_returns_one(sample_repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "f.json"
    code = main(["scan", str(sample_repo), "--output", str(out), "--fail-on", "high"])
    assert code == 1


def test_scan_fail_on_high_clean_repo_returns_zero(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text("print('ok')\n", encoding="utf-8")
    code = main(["scan", str(tmp_path), "--fail-on", "high"])
    assert code == 0


def test_scan_fail_on_medium_ignores_low_only(tmp_path: Path) -> None:
    (tmp_path / "weak.py").write_text("hashlib.md5(x)\n", encoding="utf-8")  # aive: ignore
    # A lone low-severity finding should not breach a medium gate.
    assert main(["scan", str(tmp_path), "--fail-on", "medium"]) == 0
    # ...but it does breach a low gate.
    assert main(["scan", str(tmp_path), "--fail-on", "low"]) == 1


def test_scan_rejects_invalid_fail_on_choice(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["scan", str(tmp_path), "--fail-on", "critical"])


# --------------------------------------------------------------------------- #
# plan
# --------------------------------------------------------------------------- #
def test_plan_renders_markdown_from_findings_file(sample_repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    findings = tmp_path / "f.json"
    main(["scan", str(sample_repo), "--output", str(findings)])
    capsys.readouterr()  # discard scan output

    code = main(["plan", str(findings)])
    assert code == 0
    out = capsys.readouterr().out
    assert "# AIVE Patch Plan" in out
    assert "Decision Frame" in out
    assert "Re-enable certificate verification" in out


def test_plan_writes_output_file(sample_repo: Path, tmp_path: Path) -> None:
    findings = tmp_path / "f.json"
    main(["scan", str(sample_repo), "--output", str(findings)])
    plan = tmp_path / "plan.md"
    code = main(["plan", str(findings), "--output", str(plan)])
    assert code == 0
    assert "AIVE Patch Plan" in plan.read_text(encoding="utf-8")


def test_plan_empty_findings_notes_no_signal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    findings = tmp_path / "empty.json"
    findings.write_text(json.dumps({"repo": "demo", "findings": []}), encoding="utf-8")
    main(["plan", str(findings)])
    assert "No high-signal findings" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #
def test_verify_text_output(repo_root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["verify", str(repo_root)])
    assert code == 0
    out = capsys.readouterr().out
    assert "python-syntax: pass" in out


def test_verify_json_output(repo_root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["verify", str(repo_root), "--json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    names = {c["name"] for c in data}
    assert {"python-syntax", "test-coverage-signal", "github-workflow", "repo-hygiene"} <= names


def test_verify_strict_fails_on_syntax_error(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def x(:\n", encoding="utf-8")
    assert main(["verify", str(tmp_path), "--strict"]) == 1
    # Without --strict, a failing check does not change the exit code.
    assert main(["verify", str(tmp_path)]) == 0
