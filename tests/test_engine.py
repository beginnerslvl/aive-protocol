from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from aive.cli import main as cli_main
from aive.engine import (
    MAX_SCAN_FILE_BYTES,
    build_patch_plan_markdown,
    build_scan_payload,
    iter_source_files,
    run_verification,
    scan_repository,
)


def _write(root: Path, name: str, body: str) -> None:
    (root / name).write_text(body, encoding="utf-8")


class ScanTests(unittest.TestCase):
    def test_scan_payload_detects_dynamic_exec(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write(root, "demo.py", "value = eval(user_input)\n")  # aive: ignore
            payload = build_scan_payload(root)

        self.assertEqual(payload["finding_count"], 1)
        self.assertEqual(payload["findings"][0]["rule_id"], "AIVE-PY-001")
        self.assertEqual(payload["severity_summary"]["high"], 1)

    def test_new_rules_fire(self) -> None:
        cases = {
            "os_cmd.py": ("os.system(cmd)\n", "AIVE-PY-003"),  # aive: ignore
            "deser.py": ("data = pickle.loads(blob)\n", "AIVE-PY-004"),  # aive: ignore
            "conf.py": ("cfg = yaml.load(stream)\n", "AIVE-PY-005"),  # aive: ignore
            "net.py": ("requests.get(url, verify=False)\n", "AIVE-SEC-002"),  # aive: ignore
            "hash.py": ("digest = hashlib.md5(data)\n", "AIVE-SEC-003"),  # aive: ignore
        }
        for filename, (body, expected_rule) in cases.items():
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                _write(root, filename, body)
                findings = scan_repository(root)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn(expected_rule, rule_ids, msg=f"{filename} -> {rule_ids}")

    def test_safe_yaml_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write(root, "ok.py", "cfg = yaml.safe_load(stream)\n")
            findings = scan_repository(root)
        self.assertEqual(findings, [])

    def test_suppression_marker_skips_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write(root, "demo.py", "value = eval(user_input)  # aive: ignore\n")
            findings = scan_repository(root)
        self.assertEqual(findings, [])

    def test_min_confidence_filters_low_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write(root, "hash.py", "digest = hashlib.sha1(data)\n")  # confidence 0.55  # aive: ignore
            high = build_scan_payload(root, min_confidence=0.9)
            low = build_scan_payload(root, min_confidence=0.0)
        self.assertEqual(high["finding_count"], 0)
        self.assertEqual(low["finding_count"], 1)

    def test_findings_sorted_by_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write(root, "weak.py", "digest = hashlib.md5(data)\n")  # low  # aive: ignore
            _write(root, "danger.py", "os.system(cmd)\n")  # high  # aive: ignore
            payload = build_scan_payload(root)
        severities = [f["severity"] for f in payload["findings"]]
        self.assertEqual(severities[0], "high")


class TraversalTests(unittest.TestCase):
    def test_ignored_directories_are_not_descended(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write(root, "app.py", "value = eval(user_input)\n")  # aive: ignore
            for ignored in ("node_modules", ".git", ".venv"):
                sub = root / ignored / "nested"
                sub.mkdir(parents=True)
                (sub / "vendored.py").write_text(
                    "os.system(cmd)\n", encoding="utf-8"  # aive: ignore
                )
            sources = {p.name for p in iter_source_files(root)}
            findings = scan_repository(root)
        # Only the real source file is visited; vendored trees are pruned.
        self.assertEqual(sources, {"app.py"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file_path, "app.py")

    def test_repo_under_ignored_named_path_still_scans(self) -> None:
        # A repo living inside a directory named like an ignored part (e.g.
        # ".../build/proj") must still be scanned; pruning is per-repo, not on
        # absolute-path segments.
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "build" / "proj"
            root.mkdir(parents=True)
            _write(root, "app.py", "os.system(cmd)\n")  # aive: ignore
            findings = scan_repository(root)
        self.assertEqual(len(findings), 1)

    def test_oversized_files_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            big = "# padding\n" * ((MAX_SCAN_FILE_BYTES // 10) + 1)
            _write(root, "huge.py", "value = eval(x)\n" + big)  # aive: ignore
            _write(root, "small.py", "value = eval(y)\n")  # aive: ignore
            findings = scan_repository(root)
        files = {f.file_path for f in findings}
        self.assertIn("small.py", files)
        self.assertNotIn("huge.py", files)


class PatchPlanTests(unittest.TestCase):
    def test_patch_plan_mentions_decision_frame(self) -> None:
        markdown = build_patch_plan_markdown(
            {"repo": "demo", "scanned_at": "2026-04-08T00:00:00+00:00", "findings": []}
        )
        self.assertIn("Decision Frame", markdown)
        self.assertIn("No high-signal findings", markdown)

    def test_patch_plan_covers_a_new_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write(root, "net.py", "requests.get(url, verify=False)\n")  # aive: ignore
            payload = build_scan_payload(root)
        markdown = build_patch_plan_markdown(payload)
        self.assertIn("Re-enable certificate verification", markdown)


class VerificationTests(unittest.TestCase):
    def test_verification_detects_gitignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write(root, ".gitignore", "__pycache__/\n")
            checks = run_verification(root)
        names = {check.name: check.status for check in checks}
        self.assertEqual(names["repo-hygiene"], "pass")


class CliTests(unittest.TestCase):
    def test_scan_fail_on_high_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            out = root / "findings.json"
            _write(root, "danger.py", "os.system(cmd)\n")  # aive: ignore
            code = cli_main(["scan", str(root), "--output", str(out), "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_scan_fail_on_high_passes_when_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            out = root / "findings.json"
            _write(root, "ok.py", "print('all good')\n")
            code = cli_main(["scan", str(root), "--output", str(out), "--fail-on", "high"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
