#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aive.engine import build_scan_payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a repository and emit an AIVE findings payload.")
    parser.add_argument("target", nargs="?", default=".", help="Repository path to scan.")
    parser.add_argument("--output", help="Optional file to write JSON payload to.")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    payload = build_scan_payload(target)
    rendered = json.dumps(payload, indent=2)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
