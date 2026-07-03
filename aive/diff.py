"""Baseline drift detection for AIVE scans.

The scan/plan/verify loop tells you *what is wrong right now*. In CI that is
rarely the question a reviewer actually needs answered. A pull request should
not be blocked because the repository already carried a hundred pre-existing
findings; it should be blocked when the change in front of you *introduces new
risk*. That is the job of ``aive diff``.

Given a fresh scan of the working tree and a stored baseline payload (typically
the ``main`` branch's last known-good scan), this module classifies findings
into three buckets:

- **new** — present now, absent from the baseline (regressions a PR added)
- **fixed** — present in the baseline, gone now (progress worth celebrating)
- **unchanged** — carried by both (existing debt, neither better nor worse)

The classification is line-number agnostic. Real code moves: a maintainer adds
an import above a risky call, reindents a block, or shifts a function. A naive
``(rule, file, line)`` key would report all of that churn as brand-new risk and
train reviewers to ignore the gate. Instead each finding is reduced to a stable
fingerprint of ``rule_id`` + ``file_path`` + a whitespace-normalized snippet, so
identity survives reformatting and vertical drift.

Nothing here mutates a scan; it is a pure comparison over two payloads, which
keeps it safe to run anywhere in the loop.
"""
from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
import re

from .engine import SEVERITY_ORDER

DIFF_SCHEMA = "aive.diff.v1"

_WHITESPACE = re.compile(r"\s+")

# Fields copied onto each classified finding so a downstream report can explain
# how identity was established without re-deriving it.
_FINGERPRINT_KEYS = ("rule_id", "file_path", "snippet")


def normalize_snippet(snippet: str) -> str:
    """Collapse runs of whitespace so reindentation does not change identity."""
    return _WHITESPACE.sub(" ", str(snippet)).strip()


def finding_fingerprint(finding: dict[str, object]) -> str:
    """Return a stable, line-agnostic identity for a finding.

    Two findings share a fingerprint when they come from the same rule, in the
    same file, on a snippet that is identical once whitespace is normalized.
    Line numbers are deliberately excluded so that vertical drift (added imports,
    reordered functions, reformatting) does not masquerade as new risk.
    """
    rule_id = str(finding.get("rule_id", ""))
    file_path = str(finding.get("file_path", ""))
    snippet = normalize_snippet(str(finding.get("snippet", "")))
    raw = "\x1f".join((rule_id, file_path, snippet))
    return sha256(raw.encode("utf-8")).hexdigest()[:16]


def _group_by_fingerprint(
    findings: list[dict[str, object]],
) -> dict[str, list[dict[str, object]]]:
    groups: dict[str, list[dict[str, object]]] = {}
    for finding in findings:
        groups.setdefault(finding_fingerprint(finding), []).append(finding)
    return groups


def _sort_key(finding: dict[str, object]):
    severity = str(finding.get("severity", ""))
    confidence = float(finding.get("confidence", 0.0) or 0.0)
    return (
        -SEVERITY_ORDER.get(severity, 0),
        -confidence,
        str(finding.get("file_path", "")),
        int(finding.get("line", 0) or 0),
    )


def compute_diff(
    current_findings: list[dict[str, object]],
    baseline_findings: list[dict[str, object]],
) -> dict[str, list[dict[str, object]]]:
    """Classify current findings against a baseline.

    Multiplicity is respected: if the same fingerprint appears three times now
    and once in the baseline, two instances count as new. This keeps the gate
    honest when a risky pattern is duplicated rather than merely moved.
    """
    current_groups = _group_by_fingerprint(current_findings)
    baseline_groups = _group_by_fingerprint(baseline_findings)

    new: list[dict[str, object]] = []
    fixed: list[dict[str, object]] = []
    unchanged: list[dict[str, object]] = []

    for fingerprint in set(current_groups) | set(baseline_groups):
        current_items = current_groups.get(fingerprint, [])
        baseline_items = baseline_groups.get(fingerprint, [])
        shared = min(len(current_items), len(baseline_items))

        unchanged.extend(current_items[:shared])
        if len(current_items) > shared:
            new.extend(current_items[shared:])
        if len(baseline_items) > shared:
            fixed.extend(baseline_items[shared:])

    new.sort(key=_sort_key)
    fixed.sort(key=_sort_key)
    unchanged.sort(key=_sort_key)
    return {"new": new, "fixed": fixed, "unchanged": unchanged}


def build_diff_payload(
    repo: str,
    current_findings: list[dict[str, object]],
    baseline_payload: dict[str, object],
) -> dict[str, object]:
    """Assemble the machine-friendly ``aive.diff.v1`` payload."""
    baseline_findings = list(baseline_payload.get("findings", []))  # type: ignore[arg-type]
    buckets = compute_diff(current_findings, baseline_findings)

    return {
        "schema": DIFF_SCHEMA,
        "repo": repo,
        "compared_at": datetime.now(UTC).isoformat(),
        "baseline_scanned_at": baseline_payload.get("scanned_at", "unknown"),
        "summary": {
            "new": len(buckets["new"]),
            "fixed": len(buckets["fixed"]),
            "unchanged": len(buckets["unchanged"]),
            "baseline_total": len(baseline_findings),
            "current_total": len(current_findings),
        },
        "new": buckets["new"],
        "fixed": buckets["fixed"],
        "unchanged": buckets["unchanged"],
    }


def _render_bucket(title: str, findings: list[dict[str, object]]) -> list[str]:
    lines = [f"## {title} ({len(findings)})", ""]
    if not findings:
        lines.extend(["_none_", ""])
        return lines
    for finding in findings:
        rule_id = finding.get("rule_id", "?")
        location = f"{finding.get('file_path', '?')}:{finding.get('line', '?')}"
        severity = finding.get("severity", "?")
        finding_title = finding.get("title", "finding")
        lines.append(f"- `{rule_id}` **{finding_title}** — `{location}` ({severity})")
    lines.append("")
    return lines


def build_diff_markdown(diff_payload: dict[str, object]) -> str:
    """Render a reviewer-facing drift report."""
    summary = diff_payload.get("summary", {})  # type: ignore[assignment]
    new_count = int(summary.get("new", 0)) if isinstance(summary, dict) else 0

    verdict = (
        "REGRESSION — this change introduces findings absent from the baseline."
        if new_count > 0
        else "CLEAN — no findings beyond the established baseline."
    )

    lines = [
        "# AIVE Baseline Drift Report",
        "",
        f"- Repository: `{diff_payload.get('repo', 'unknown')}`",
        f"- Compared at: `{diff_payload.get('compared_at', 'unknown')}`",
        f"- Baseline scan: `{diff_payload.get('baseline_scanned_at', 'unknown')}`",
        "",
        f"**Verdict:** {verdict}",
        "",
    ]

    if isinstance(summary, dict):
        lines.extend(
            [
                "| Bucket | Count |",
                "| --- | --- |",
                f"| New (regressions) | {summary.get('new', 0)} |",
                f"| Fixed | {summary.get('fixed', 0)} |",
                f"| Unchanged (existing debt) | {summary.get('unchanged', 0)} |",
                f"| Baseline total | {summary.get('baseline_total', 0)} |",
                f"| Current total | {summary.get('current_total', 0)} |",
                "",
            ]
        )

    lines.extend(_render_bucket("New findings", list(diff_payload.get("new", []))))  # type: ignore[arg-type]
    lines.extend(_render_bucket("Fixed findings", list(diff_payload.get("fixed", []))))  # type: ignore[arg-type]
    lines.extend(
        _render_bucket("Unchanged findings", list(diff_payload.get("unchanged", [])))  # type: ignore[arg-type]
    )

    return "\n".join(lines).rstrip() + "\n"
