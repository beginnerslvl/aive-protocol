"""Alternate output renderers for AIVE scan payloads.

`aive scan` emits the canonical machine JSON payload by default. This module
adds two human-facing variants selected with ``--format``:

    json     canonical machine payload (default, byte-for-byte unchanged)
    plain    verbose, grouped-by-severity report for reading in a terminal
    compact  one dense line per finding for quick triage / grep pipelines

Keeping the renderers in a standalone module means the payload built in
``engine.build_scan_payload`` stays the single source of truth: these
functions only reshape an already-built payload for display, so alternate
formats never touch the scan pipeline itself.
"""
from __future__ import annotations

import json
from typing import Iterable

FORMAT_CHOICES = ("json", "plain", "compact")

# Ordering used when grouping findings for the plain report (highest first).
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}

# ASCII severity tags. Deliberately plain text (no color / unicode) so the
# output stays safe to pipe, grep, and diff on any terminal or CI log.
_SEVERITY_TAG = {"high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}


def _findings(payload: dict[str, object]) -> list[dict]:
    raw = payload.get("findings", [])
    return list(raw) if isinstance(raw, Iterable) else []


def render_json(payload: dict[str, object]) -> str:
    """Canonical machine format — identical to the historical default."""
    return json.dumps(payload, indent=2)


def render_compact(payload: dict[str, object]) -> str:
    """One line per finding: severity tag, rule, location, confidence, title.

    Designed for fast eyeball triage and for feeding ``grep``/``awk``. When
    there are no findings a single ``clean`` marker line is emitted so the
    output is never empty.
    """
    findings = _findings(payload)
    if not findings:
        return f"clean  {payload.get('repo', '?')}  0 findings"

    lines = []
    for f in findings:
        tag = _SEVERITY_TAG.get(str(f.get("severity")), "[????]")
        location = f"{f.get('file_path', '?')}:{f.get('line', '?')}"
        conf = float(f.get("confidence", 0.0))
        lines.append(
            f"{tag} {str(f.get('rule_id', '?')):<11} {location:<32} "
            f"c={conf:.2f}  {f.get('title', '')}"
        )
    return "\n".join(lines)


def render_plain(payload: dict[str, object]) -> str:
    """Verbose, grouped-by-severity report for terminal reading."""
    findings = _findings(payload)
    summary = payload.get("severity_summary", {}) or {}

    header = [
        "AIVE Scan Report",
        "=" * 48,
        f"repo         : {payload.get('repo', '?')}",
        f"scanned_at   : {payload.get('scanned_at', '?')}",
        f"findings     : {payload.get('finding_count', len(findings))}",
        f"by severity  : high={summary.get('high', 0)} "
        f"medium={summary.get('medium', 0)} low={summary.get('low', 0)}",
        "",
    ]

    if not findings:
        header.append("No findings at the current confidence threshold.")
        return "\n".join(header)

    ordered = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_RANK.get(str(f.get("severity")), 9),
            -float(f.get("confidence", 0.0)),
        ),
    )

    body: list[str] = []
    current_sev: str | None = None
    for f in ordered:
        sev = str(f.get("severity"))
        if sev != current_sev:
            current_sev = sev
            body.append(f"--- {sev.upper()} ---")
        tag = _SEVERITY_TAG.get(sev, "[????]")
        body.append(f"{tag} {f.get('title', '')}  ({f.get('rule_id', '?')})")
        body.append(f"    location   : {f.get('file_path', '?')}:{f.get('line', '?')}")
        body.append(f"    confidence : {float(f.get('confidence', 0.0)):.2f}")
        body.append(f"    blast      : {f.get('blast_radius', '?')}")
        body.append(f"    hypothesis : {f.get('exploit_hypothesis', '')}")
        body.append(f"    snippet    : {f.get('snippet', '')}")
        body.append("")

    return "\n".join(header + body).rstrip()


_RENDERERS = {
    "json": render_json,
    "plain": render_plain,
    "compact": render_compact,
}


def render_scan(payload: dict[str, object], fmt: str = "json") -> str:
    """Render a scan payload in one of ``FORMAT_CHOICES``.

    Falls back to JSON for an unknown format so callers can never end up
    with no output.
    """
    return _RENDERERS.get(fmt, render_json)(payload)
