"""End-to-end smoke tests that drive the real CLI as a subprocess.

These invoke ``python -m aive`` (the same code path as the installed ``aive``
console script) across the full scan -> plan -> verify loop, asserting on
process exit codes and the files/stdout produced. They catch packaging and
argument-wiring regressions that in-process tests can miss.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# Invoke the CLI exactly as a user would, but pinned to the test interpreter.
CLI = [sys.executable, "-m", "aive"]


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        CLI + args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def vuln_repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        "import os\n\n\ndef deploy(branch):\n    os.system('deploy ' + branch)\n",  # aive: ignore
        encoding="utf-8",
    )
    (tmp_path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    return tmp_path


def test_module_entrypoint_reports_version() -> None:
    result = _run(["--version"])
    assert result.returncode == 0
    assert "aive" in result.stdout


def test_full_pipeline_scan_plan_verify(vuln_repo: Path, tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    findings = artifacts / "findings.json"
    plan = artifacts / "patch-plan.md"

    # 1. scan -> findings.json
    scan = _run(["scan", str(vuln_repo), "--output", str(findings), "--min-confidence", "0.8"])
    assert scan.returncode == 0, scan.stderr
    payload = json.loads(findings.read_text(encoding="utf-8"))
    assert payload["finding_count"] >= 1
    assert any(f["rule_id"] == "AIVE-PY-003" for f in payload["findings"])

    # 2. plan -> patch-plan.md
    planned = _run(["plan", str(findings), "--output", str(plan)])
    assert planned.returncode == 0, planned.stderr
    plan_text = plan.read_text(encoding="utf-8")
    assert "AIVE Patch Plan" in plan_text
    assert "Swap os.system for subprocess.run" in plan_text

    # 3. verify --json --strict on a clean, syntactically valid repo -> exit 0
    verified = _run(["verify", str(vuln_repo), "--json", "--strict"])
    assert verified.returncode == 0, verified.stderr
    checks = json.loads(verified.stdout)
    assert {c["name"] for c in checks} >= {"python-syntax", "repo-hygiene"}


def test_scan_fail_on_high_gates_the_process(vuln_repo: Path) -> None:
    # os.system finding is high severity -> the gate must exit non-zero.
    result = _run(["scan", str(vuln_repo), "--fail-on", "high"])
    assert result.returncode == 1


def test_verify_strict_nonzero_on_syntax_error(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    result = _run(["verify", str(tmp_path), "--strict"])
    assert result.returncode == 1


@pytest.mark.skipif(shutil.which("aive") is None, reason="aive console script not on PATH")
def test_installed_console_script_runs(tmp_path: Path) -> None:
    """When installed (pip install -e .), the ``aive`` script itself works."""
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    result = subprocess.run(
        ["aive", "scan", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["schema"] == "aive.scan.v1"
