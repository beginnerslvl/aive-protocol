"""Tests for the dataclasses in ``aive.models``."""
from __future__ import annotations

from aive.models import Finding, PatchOption, VerificationCheck


def test_finding_to_dict_roundtrip() -> None:
    finding = Finding(
        rule_id="AIVE-PY-001",
        title="Dynamic code execution",
        file_path="a/b.py",
        line=7,
        severity="high",
        confidence=0.92,
        snippet="eval(x)",  # aive: ignore
        blast_radius="localized",
        exploit_hypothesis="reachable sink",
    )
    data = finding.to_dict()
    assert data["rule_id"] == "AIVE-PY-001"
    assert data["line"] == 7
    # A payload dict must be able to rehydrate a Finding (used by plan rendering).
    assert Finding(**data) == finding


def test_patch_option_defaults_to_empty_safety_notes() -> None:
    option = PatchOption(title="t", summary="s")
    assert option.safety_notes == []
    assert option.to_dict()["safety_notes"] == []


def test_patch_option_safety_notes_are_independent_instances() -> None:
    a = PatchOption(title="a", summary="s")
    b = PatchOption(title="b", summary="s")
    a.safety_notes.append("note")
    assert b.safety_notes == [], "default_factory must not share list state"


def test_verification_check_to_dict() -> None:
    check = VerificationCheck(name="python-syntax", status="pass", details="ok")
    assert check.to_dict() == {"name": "python-syntax", "status": "pass", "details": "ok"}
