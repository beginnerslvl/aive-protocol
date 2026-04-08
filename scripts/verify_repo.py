#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aive.engine import run_verification


def main() -> int:
    parser = argparse.ArgumentParser(description="Run lightweight verification checks for an AIVE target repo.")
    parser.add_argument("target", nargs="?", default=".", help="Repository path to verify.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of markdown-style text.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when any verification check fails.")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    checks = run_verification(target)

    if args.json:
        print(json.dumps([check.to_dict() for check in checks], indent=2))
    else:
        for check in checks:
            print(f"- {check.name}: {check.status} ({check.details})")

    failed = any(check.status == "fail" for check in checks)
    return 1 if args.strict and failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
