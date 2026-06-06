"""Unit tests for the pure engine functions.

These cover the internal building blocks that the CLI and scripts compose:
source discovery, blast-radius classification, severity accounting, payload
shaping, patch-option selection, and the verification checks. They complement
the higher-level flow tests in ``test_engine.py`` and ``test_cli.py``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from aive.engine import (
    IGNORED_PARTS,
    RULES,
    SEVERITY_ORDER,
    blast_radius_for,
    build_scan_payload,
    iter_source_files,
    patch_options_for,
    run_verification,
    scan_repository,
    summarize_severity,
)
from aive.models import Finding


# --------------------------------------------------------------------------- #
# iter_source_files
# --------------------------------------------------------------------------- #
def test_iter_source_files_filters_by_suffix(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "keep.ts").write_text("const x = 1;\n", encoding="utf-8")
    (tmp_path / "skip.md").write_text("# doc\n", encoding="utf-8")
    (tmp_path / "skip.png").write_bytes(b"\x89PNG")

    found = {p.name for p in iter_source_files(tmp_path)}
    assert found == {"keep.py", "keep.ts"}


@pytest.mark.parametrize("ignored", sorted(IGNORED_PARTS))
def test_iter_source_files_skips_ignored_directories(tmp_path: Path, ignored: str) -> None:
    nested = tmp_path / ignored
    nested.mkdir()
    (nested / "buried.py").write_text("eval(x)\n", encoding="utf-8")  # aive: ignore
    (tmp_path / "top.py").write_text("y = 2\n", encoding="utf-8")

    names = {p.name for p in iter_source_files(tmp_path)}
    assert names == {"top.py"}


def test_iter_source_files_recurses_into_subdirs(tmp_path: Path) -> None:
    sub = tmp_path / "pkg" / "inner"
    sub.mkdir(parents=True)
    (sub / "deep.py").write_text("z = 3\n", encoding="utf-8")
    assert [p.name for p in iter_source_files(tmp_path)] == ["deep.py"]


# --------------------------------------------------------------------------- #
# blast_radius_for
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "relpath, expected",
    [
        (Path("auth/login.py"), "broad"),
        (Path(".github/workflows/ci.yml"), "broad"),
        (Path("api/routes.py"), "broad"),
        (Path("cli/main.py"), "moderate"),
        (Path("scripts/run.py"), "moderate"),
        (Path("tools/helper.py"), "moderate"),
        (Path("src/util.py"), "localized"),
        (Path("readme_helper.py"), "localized"),
    ],
)
def test_blast_radius_classification(relpath: Path, expected: str) -> None:
    assert blast_radius_for(relpath) == expected


# --------------------------------------------------------------------------- #
# summarize_severity
# --------------------------------------------------------------------------- #
def test_summarize_severity_counts_each_tier() -> None:
    findings = [
        _finding(severity="high"),
        _finding(severity="high"),
        _finding(severity="medium"),
        _finding(severity="low"),
    ]
    assert summarize_severity(findings) == {"high": 2, "medium": 1, "low": 1}


def test_summarize_severity_empty() -> None:
    assert summarize_severity([]) == {"high": 0, "medium": 0, "low": 0}


# --------------------------------------------------------------------------- #
# build_scan_payload
# --------------------------------------------------------------------------- #
def test_scan_payload_schema_and_repo_name(sample_repo: Path) -> None:
    payload = build_scan_payload(sample_repo)
    assert payload["schema"] == "aive.scan.v1"
    assert payload["repo"] == sample_repo.name
    assert payload["finding_count"] == len(payload["findings"])
    assert isinstance(payload["scanned_at"], str)


def test_scan_payload_sorted_by_severity_then_confidence(sample_repo: Path) -> None:
    payload = build_scan_payload(sample_repo)
    ranks = [SEVERITY_ORDER[f["severity"]] for f in payload["findings"]]
    assert ranks == sorted(ranks, reverse=True), "findings must be high-severity first"
    # sample_repo seeds exactly one high / one medium / one low finding.
    assert payload["severity_summary"] == {"high": 1, "medium": 1, "low": 1}


def test_scan_payload_min_confidence_boundary_is_inclusive(tmp_path: Path) -> None:
    # AIVE-SEC-003 (weak hash) has confidence 0.55 exactly.
    (tmp_path / "h.py").write_text("hashlib.md5(x)\n", encoding="utf-8")  # aive: ignore
    at_boundary = build_scan_payload(tmp_path, min_confidence=0.55)
    above = build_scan_payload(tmp_path, min_confidence=0.56)
    assert at_boundary["finding_count"] == 1
    assert above["finding_count"] == 0


# --------------------------------------------------------------------------- #
# scan_repository rule coverage
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "body, rule_id",
    [
        ("value = eval(data)\n", "AIVE-PY-001"),  # aive: ignore
        ("subprocess.run(cmd, shell=True)\n", "AIVE-PY-002"),  # aive: ignore
        ("os.popen(cmd)\n", "AIVE-PY-003"),  # aive: ignore
        ("pickle.load(fh)\n", "AIVE-PY-004"),  # aive: ignore
        ("yaml.load(stream)\n", "AIVE-PY-005"),  # aive: ignore
        ("api_key = 'sk-abc123'\n", "AIVE-SEC-001"),  # aive: ignore
        ("requests.get(u, verify=False)\n", "AIVE-SEC-002"),  # aive: ignore
        ("hashlib.sha1(x)\n", "AIVE-SEC-003"),  # aive: ignore
    ],
)
def test_every_rule_fires_on_a_representative_line(tmp_path: Path, body: str, rule_id: str) -> None:
    (tmp_path / "case.py").write_text(body, encoding="utf-8")
    rule_ids = {f.rule_id for f in scan_repository(tmp_path)}
    assert rule_id in rule_ids


def test_rule_registry_ids_are_unique() -> None:
    ids = [rule["rule_id"] for rule in RULES]
    assert len(ids) == len(set(ids))


def test_scan_records_line_number_and_snippet(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("a = 1\nb = eval(payload)\n", encoding="utf-8")  # aive: ignore
    findings = scan_repository(tmp_path)
    assert len(findings) == 1
    assert findings[0].line == 2
    assert findings[0].snippet == "b = eval(payload)"  # aive: ignore
    assert findings[0].file_path == "m.py"


# --------------------------------------------------------------------------- #
# patch_options_for
# --------------------------------------------------------------------------- #
def test_patch_options_uses_rule_specific_first_option() -> None:
    finding = _finding(rule_id="AIVE-SEC-002")
    options = patch_options_for(finding)
    assert options[0].title == "Re-enable certificate verification"
    # The two common options are always appended.
    titles = [o.title for o in options]
    assert "Reproduce the exploit path" in titles
    assert "Ship behind a narrow branch" in titles


def test_patch_options_falls_back_for_unknown_rule() -> None:
    finding = _finding(rule_id="AIVE-UNKNOWN-999")
    options = patch_options_for(finding)
    assert options[0].title == "Contain and verify the pattern"
    assert len(options) == 3


# --------------------------------------------------------------------------- #
# run_verification
# --------------------------------------------------------------------------- #
def test_verification_flags_syntax_errors(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def oops(:\n", encoding="utf-8")
    checks = {c.name: c for c in run_verification(tmp_path)}
    assert checks["python-syntax"].status == "fail"
    assert "broken.py" in checks["python-syntax"].details


def test_verification_warns_when_scaffolding_absent(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    checks = {c.name: c.status for c in run_verification(tmp_path)}
    assert checks["python-syntax"] == "pass"
    assert checks["test-coverage-signal"] == "warn"
    assert checks["github-workflow"] == "warn"
    assert checks["repo-hygiene"] == "warn"


def test_verification_passes_on_real_repo(repo_root: Path) -> None:
    checks = {c.name: c.status for c in run_verification(repo_root)}
    assert checks["python-syntax"] == "pass"
    assert checks["test-coverage-signal"] == "pass"
    assert checks["github-workflow"] == "pass"
    assert checks["repo-hygiene"] == "pass"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _finding(**overrides: object) -> Finding:
    base = dict(
        rule_id="AIVE-PY-001",
        title="Dynamic code execution",
        file_path="demo.py",
        line=1,
        severity="high",
        confidence=0.9,
        snippet="eval(x)",  # aive: ignore
        blast_radius="localized",
        exploit_hypothesis="hypothetical",
    )
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]
