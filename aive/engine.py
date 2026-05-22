from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
import os
import re

from .models import Finding, PatchOption, VerificationCheck

# Files larger than this are skipped by the scanner. Real source rarely exceeds
# a few megabytes; anything past this cap is almost always a minified bundle,
# generated blob, or vendored artifact. Line-scanning such files with every
# rule regex is pure cost, so we stat first and skip before reading — bounding
# both time and peak memory on pathological inputs.
MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024

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

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

# A line carrying this marker is deliberately skipped by the scanner. It lets a
# maintainer annotate an intentional pattern (a rule definition, a test fixture,
# a reviewed false positive) so the loop does not re-flag it every run.
SUPPRESS_MARKER = re.compile(r"#\s*aive:\s*ignore\b")

RULES = [
    {
        "rule_id": "AIVE-PY-001",
        "title": "Dynamic code execution",
        "pattern": re.compile(r"\b(?:eval|exec)\s*\("),  # aive: ignore
        "severity": "high",
        "confidence": 0.92,
        "hypothesis": "attacker-controlled input may reach a dynamic execution sink",
    },
    {
        "rule_id": "AIVE-PY-002",
        "title": "Shell execution with interpolation risk",
        "pattern": re.compile(r"subprocess\.[a-z_]+\([^)]*shell\s*=\s*True"),  # aive: ignore
        "severity": "high",
        "confidence": 0.88,
        "hypothesis": "string interpolation into a shell command may allow command injection",
    },
    {
        "rule_id": "AIVE-PY-003",
        "title": "Direct OS command execution",
        "pattern": re.compile(r"\bos\.(?:system|popen)\s*\("),  # aive: ignore
        "severity": "high",
        "confidence": 0.83,
        "hypothesis": "a raw OS command call can be steered by unsanitised input",
    },
    {
        "rule_id": "AIVE-PY-004",
        "title": "Unsafe deserialization",
        "pattern": re.compile(r"\b(?:pickle|cPickle)\.loads?\s*\("),  # aive: ignore
        "severity": "high",
        "confidence": 0.8,
        "hypothesis": "deserializing untrusted data can execute arbitrary objects on load",
    },
    {
        "rule_id": "AIVE-PY-005",
        "title": "Unsafe YAML load",
        "pattern": re.compile(r"yaml\.load\s*\((?![^)]*Safe)"),  # aive: ignore
        "severity": "medium",
        "confidence": 0.74,
        "hypothesis": "yaml.load without a safe loader can instantiate arbitrary types",
    },
    {
        "rule_id": "AIVE-SEC-001",
        "title": "Hard-coded credential marker",
        "pattern": re.compile(r"(api[_-]?key|secret|token|password)\s*=\s*[\"'][^\"']+[\"']"),  # aive: ignore
        "severity": "medium",
        "confidence": 0.76,
        "hypothesis": "embedded credentials widen blast radius and complicate patch hygiene",
    },
    {
        "rule_id": "AIVE-SEC-002",
        "title": "TLS verification disabled",
        "pattern": re.compile(r"verify\s*=\s*False"),  # aive: ignore
        "severity": "medium",
        "confidence": 0.7,
        "hypothesis": "disabling certificate verification exposes traffic to interception",
    },
    {
        "rule_id": "AIVE-SEC-003",
        "title": "Weak hashing primitive",
        "pattern": re.compile(r"hashlib\.(?:md5|sha1)\s*\("),  # aive: ignore
        "severity": "low",
        "confidence": 0.55,
        "hypothesis": "md5/sha1 are unsuitable for security-sensitive hashing",
    },
]


def _walk_pruned(root: Path) -> Iterator[Path]:
    """Yield every file under ``root``, never descending into ignored trees.

    ``root.rglob('*')`` walks the entire tree first and only then filters out
    ``.git``/``node_modules``/``.venv``/... — paying full I/O and a ``stat`` for
    files it always discards. ``os.walk`` lets us prune those directories *in
    place* so we never enter them, which is decisive on real repositories where
    vendored trees dwarf the actual source. Pruning is evaluated on directory
    names within the repo (not on absolute-path segments), so a repo that
    happens to live under e.g. ``/home/build/...`` scans correctly.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in IGNORED_PARTS]
        base = Path(dirpath)
        for name in filenames:
            yield base / name


def iter_source_files(root: Path) -> Iterator[Path]:
    for path in _walk_pruned(root):
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if not path.is_file():
            continue
        yield path


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
            if path.stat().st_size > MAX_SCAN_FILE_BYTES:
                continue
        except OSError:
            continue

        # Hoist the per-file relative path and blast radius out of the hot loop:
        # the original recomputed ``relative_to`` twice *per finding*. Compute
        # them once per file instead.
        relative = path.relative_to(root)
        rel_posix = relative.as_posix()
        blast_radius = blast_radius_for(relative)

        # Stream the file line by line so peak memory stays bounded by a single
        # line regardless of file size (the old code loaded the whole file and
        # built a full list of its lines up front). Findings are buffered
        # per-file so that a mid-file decode error discards the whole file,
        # preserving the original "skip undecodable files" semantics.
        file_findings: list[Finding] = []
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line_number, raw in enumerate(handle, start=1):
                    line = raw.rstrip("\n")
                    if SUPPRESS_MARKER.search(line):
                        continue
                    for rule in RULES:
                        if not rule["pattern"].search(line):
                            continue
                        file_findings.append(
                            Finding(
                                rule_id=str(rule["rule_id"]),
                                title=str(rule["title"]),
                                file_path=rel_posix,
                                line=line_number,
                                severity=str(rule["severity"]),
                                confidence=float(rule["confidence"]),
                                snippet=line.strip()[:180],
                                blast_radius=blast_radius,
                                exploit_hypothesis=str(rule["hypothesis"]),
                            )
                        )
        except (UnicodeDecodeError, OSError):
            continue

        findings.extend(file_findings)
    return findings


def summarize_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def build_scan_payload(root: Path, min_confidence: float = 0.0) -> dict[str, object]:
    findings = [
        finding
        for finding in scan_repository(root)
        if finding.confidence >= min_confidence
    ]
    findings.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -f.confidence, f.file_path, f.line)
    )
    return {
        "schema": "aive.scan.v1",
        "repo": root.resolve().name,
        "scanned_at": datetime.now(UTC).isoformat(),
        "finding_count": len(findings),
        "severity_summary": summarize_severity(findings),
        "findings": [finding.to_dict() for finding in findings],
    }


COMMON_PATCH_OPTIONS = [
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

# Rule-specific first-choice remediation. Keeping this as a registry means a new
# detection rule and its preferred fix stay side by side and easy to extend.
SPECIFIC_PATCH_OPTIONS: dict[str, PatchOption] = {
    "AIVE-PY-001": PatchOption(
        title="Replace dynamic execution with an allowlisted dispatcher",
        summary="Map supported actions to explicit callables instead of evaluating raw expressions or code strings.",
        safety_notes=["Reject unknown actions.", "Record rejected inputs for follow-up triage."],
    ),
    "AIVE-PY-002": PatchOption(
        title="Remove shell parsing and pass argv explicitly",
        summary="Construct the command as a list and keep shell interpretation disabled.",
        safety_notes=["Validate user-controlled fragments.", "Prefer stable command templates."],
    ),
    "AIVE-PY-003": PatchOption(
        title="Swap os.system for subprocess.run with an argv list",
        summary="Call subprocess.run([...], shell=False) so arguments are never re-parsed by a shell.",
        safety_notes=["Never interpolate user input into the command string.", "Fail closed on unexpected arguments."],
    ),
    "AIVE-PY-004": PatchOption(
        title="Replace pickle with a schema-checked format",
        summary="Deserialize untrusted data with JSON or a validated schema rather than pickle.",
        safety_notes=["Only unpickle data you produced yourself.", "Add a signature or integrity check if pickle is unavoidable."],
    ),
    "AIVE-PY-005": PatchOption(
        title="Load YAML through yaml.safe_load",
        summary="Use yaml.safe_load (or SafeLoader) so only plain data types are constructed.",
        safety_notes=["Reserve full YAML tags for trusted internal config only.", "Validate the parsed structure before use."],
    ),
    "AIVE-SEC-001": PatchOption(
        title="Move secrets into a managed store",
        summary="Replace inline credentials with environment-backed or secret-manager-backed retrieval.",
        safety_notes=["Rotate any exposed material.", "Search history and CI logs for leakage."],
    ),
    "AIVE-SEC-002": PatchOption(
        title="Re-enable certificate verification",
        summary="Remove verify=False and trust the system CA bundle, or pin an explicit CA path.",  # aive: ignore
        safety_notes=["Never ship verify=False to production.", "Fix the root cause (expired or self-signed cert) instead."],  # aive: ignore
    ),
    "AIVE-SEC-003": PatchOption(
        title="Upgrade to a modern hashing primitive",
        summary="Use SHA-256+ for integrity and a slow KDF (bcrypt/argon2/scrypt) for passwords.",
        safety_notes=["Keep md5/sha1 only for non-security checksums.", "Migrate stored hashes on next authentication."],
    ),
}


def patch_options_for(finding: Finding) -> list[PatchOption]:
    specific = SPECIFIC_PATCH_OPTIONS.get(finding.rule_id)
    if specific is None:
        specific = PatchOption(
            title="Contain and verify the pattern",
            summary="Scope the risky call, add a reproduction, and gate the fix behind independent verification.",
            safety_notes=["Confirm reachability before patching.", "Prefer the least-surprising safe default."],
        )
    return [specific, *COMMON_PATCH_OPTIONS]


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

    has_tests = (root / "tests").exists() or any(
        path.name.startswith("test_") and path.suffix == ".py"
        for path in _walk_pruned(root)
    )
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
