from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import re

from .models import Finding, PatchOption, VerificationCheck

TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".sh",
    ".yml",
    ".yaml",
}

IGNORED_PARTS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "artifacts",
    "dist",
    "build",
}

RULES = [
    {
        "rule_id": "AIVE-PY-001",
        "title": "Dynamic code execution",
        "pattern": re.compile(r"\b(?:eval|exec)\s*\("),
        "severity": "high",
        "confidence": 0.92,
        "hypothesis": "attacker-controlled input may reach a dynamic execution sink",
    },
    {
        "rule_id": "AIVE-PY-002",
        "title": "Shell execution with interpolation risk",
        "pattern": re.compile(r"subprocess\.[a-z_]+\([^)]*shell\s*=\s*True"),
        "severity": "high",
        "confidence": 0.88,
        "hypothesis": "string interpolation into a shell command may allow command injection",
    },
    {
        "rule_id": "AIVE-SEC-001",
        "title": "Hard-coded credential marker",
        "pattern": re.compile(r"(api[_-]?key|secret|token)\s*=\s*[\"'][^\"']+[\"']"),
        "severity": "medium",
        "confidence": 0.76,
        "hypothesis": "embedded credentials widen blast radius and complicate patch hygiene",
    },
]


def iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        files.append(path)
    return files


def blast_radius_for(path: Path) -> str:
    parts = set(path.parts)
    if {".github", "api", "auth", "routes", "deploy", "workflow"} & parts:
        return "broad"
    if {"cli", "scripts", "tools"} & parts:
        return "moderate"
    return "localized"


def scan_repository(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_source_files(root):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue

        for line_number, line in enumerate(lines, start=1):
            for rule in RULES:
                if not rule["pattern"].search(line):
                    continue
                findings.append(
                    Finding(
                        rule_id=str(rule["rule_id"]),
                        title=str(rule["title"]),
                        file_path=path.relative_to(root).as_posix(),
                        line=line_number,
                        severity=str(rule["severity"]),
                        confidence=float(rule["confidence"]),
                        snippet=line.strip()[:180],
                        blast_radius=blast_radius_for(path.relative_to(root)),
                        exploit_hypothesis=str(rule["hypothesis"]),
                    )
                )
    return findings


def build_scan_payload(root: Path) -> dict[str, object]:
    findings = scan_repository(root)
    return {
        "schema": "aive.scan.v1",
        "repo": root.resolve().name,
        "scanned_at": datetime.now(UTC).isoformat(),
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }


def patch_options_for(finding: Finding) -> list[PatchOption]:
    common = [
        PatchOption(
            title="Reproduce the exploit path",
            summary="Write the smallest failing test or proof that confirms the issue is real before changing behavior.",
            safety_notes=["Avoid patching from pattern match alone.", "Preserve a replay artifact for verifier agents."],
        ),
        PatchOption(
            title="Ship behind a narrow branch",
            summary="Apply the fix in an isolated branch and require independent verification before merge.",
            safety_notes=["Do not patch directly on main.", "Attach regression results to the PR body."],
        ),
    ]

    if finding.rule_id == "AIVE-PY-001":
        specific = PatchOption(
            title="Replace dynamic execution with an allowlisted dispatcher",
            summary="Map supported actions to explicit callables instead of evaluating raw expressions or code strings.",
            safety_notes=["Reject unknown actions.", "Record rejected inputs for follow-up triage."],
        )
    elif finding.rule_id == "AIVE-PY-002":
        specific = PatchOption(
            title="Remove shell parsing and pass argv explicitly",
            summary="Construct the command as a list and keep shell interpretation disabled.",
            safety_notes=["Validate user-controlled fragments.", "Prefer stable command templates."],
        )
    else:
        specific = PatchOption(
            title="Move secrets into a managed store",
            summary="Replace inline credentials with environment-backed or secret-manager-backed retrieval.",
            safety_notes=["Rotate any exposed material.", "Search history and CI logs for leakage."],
        )

    return [specific, *common]


def build_patch_plan_markdown(payload: dict[str, object]) -> str:
    findings = [Finding(**item) for item in payload.get("findings", [])]
    repo = payload.get("repo", "unknown-repo")
    scanned_at = payload.get("scanned_at", "unknown-time")

    lines = [
        "# AIVE Patch Plan",
        "",
        f"- Repository: `{repo}`",
        f"- Scan timestamp: `{scanned_at}`",
        f"- Findings: `{len(findings)}`",
        "",
        "## Decision Frame",
        "",
        "This report treats each finding as an exploit-to-patch candidate. The question is not only whether a risky pattern exists, but whether it is reproducible, how far it can spread, and which safe patch path should be promoted toward merge.",
        "",
    ]

    if not findings:
        lines.extend(
            [
                "## Result",
                "",
                "No high-signal findings were detected by the lightweight ruleset.",
                "",
            ]
        )
        return "\n".join(lines)

    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"## Finding {index}: {finding.title}",
                "",
                f"- Record ID: `{finding.rule_id}`",
                f"- Location: `{finding.file_path}:{finding.line}`",
                f"- Severity: `{finding.severity}`",
                f"- Confidence: `{finding.confidence:.2f}`",
                f"- Blast radius: `{finding.blast_radius}`",
                f"- Exploit hypothesis: {finding.exploit_hypothesis}",
                f"- Trigger snippet: `{finding.snippet}`",
                "",
                "### Patch Options",
                "",
            ]
        )
        for option in patch_options_for(finding):
            lines.append(f"- **{option.title}**: {option.summary}")
            for note in option.safety_notes:
                lines.append(f"  - {note}")
        lines.extend(
            [
                "",
                "### Merge Gate",
                "",
                "- one agent proposes the patch",
                "- independent agents reproduce and compare the result",
                "- regression checks must pass before merge eligibility",
                "",
            ]
        )

    return "\n".join(lines)


def run_verification(root: Path) -> list[VerificationCheck]:
    checks: list[VerificationCheck] = []
    python_files = [path for path in iter_source_files(root) if path.suffix == ".py"]

    syntax_errors: list[str] = []
    for path in python_files:
        try:
            source = path.read_text(encoding="utf-8")
            compile(source, path.as_posix(), "exec")
        except (SyntaxError, UnicodeDecodeError) as exc:
            syntax_errors.append(f"{path.relative_to(root).as_posix()}: {exc}")

    if syntax_errors:
        checks.append(
            VerificationCheck(
                name="python-syntax",
                status="fail",
                details="; ".join(syntax_errors[:3]),
            )
        )
    else:
        checks.append(
            VerificationCheck(
                name="python-syntax",
                status="pass",
                details=f"validated {len(python_files)} Python files",
            )
        )

    has_tests = any(root.rglob("test_*.py")) or (root / "tests").exists()
    checks.append(
        VerificationCheck(
            name="test-coverage-signal",
            status="pass" if has_tests else "warn",
            details="tests detected" if has_tests else "no tests discovered",
        )
    )

    has_workflow = (root / ".github" / "workflows").exists()
    checks.append(
        VerificationCheck(
            name="github-workflow",
            status="pass" if has_workflow else "warn",
            details="workflow directory present" if has_workflow else "no workflow directory found",
        )
    )

    has_gitignore = (root / ".gitignore").exists()
    checks.append(
        VerificationCheck(
            name="repo-hygiene",
            status="pass" if has_gitignore else "warn",
            details=".gitignore present" if has_gitignore else ".gitignore missing",
        )
    )

    return checks
