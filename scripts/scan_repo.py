#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aive.engine import SEVERITY_ORDER, build_scan_payload

SEVERITY_CHOICES = ("low", "medium", "high")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a repository and emit an AIVE findings payload.")
    parser.add_argument("target", nargs="?", default=".", help="Repository path to scan.")
    parser.add_argument("--output", help="Optional file to write JSON payload to.")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Drop findings below this confidence (0.0-1.0).",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES,
        help="Exit non-zero when a finding of this severity or higher is present (for CI gating).",
    )
    args = parser.parse_args(argv)

    target = Path(args.target).resolve()
    payload = build_scan_payload(target, min_confidence=args.min_confidence)
    rendered = json.dumps(payload, indent=2)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        breached = any(
            SEVERITY_ORDER.get(str(finding["severity"]), 0) >= threshold
            for finding in payload["findings"]
        )
        if breached:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
