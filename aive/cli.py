"""Unified command-line entry point for the AIVE toolkit.

Exposes the three loop stages behind one command:

    aive scan   <path> [--output F] [--min-confidence X] [--fail-on SEV]
    aive plan   <findings.json> [--output F]
    aive verify <path> [--json] [--strict]

The standalone scripts in ``scripts/`` remain for the GitHub Actions workflow;
this module is what ``pip install`` wires up as the ``aive`` console command.

The CLI is written to behave well in non-interactive contexts: it degrades
cleanly when stdout is piped or redirected, honours ``NO_COLOR`` /
``FORCE_COLOR`` / ``--no-color``, survives a closed pipe (``| head``) and
Ctrl-C without dumping a traceback, and turns filesystem and JSON problems into
short, actionable error messages on stderr instead of stack traces.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import sys
from pathlib import Path

from . import __version__
from ._terminal import Palette, should_use_color
from .engine import (
    SEVERITY_ORDER,
    build_patch_plan_markdown,
    build_scan_payload,
    run_verification,
)

SEVERITY_CHOICES = ("low", "medium", "high")

# Exit codes: 0 ok, 1 policy breach (fail-on / --strict), 2 usage/runtime error.
EXIT_OK = 0
EXIT_POLICY = 1
EXIT_ERROR = 2


def _err(message: str) -> None:
    """Write a short, prefixed diagnostic to stderr."""
    print(f"aive: error: {message}", file=sys.stderr)


def _confidence(raw: str) -> float:
    """argparse type for --min-confidence: a float within [0.0, 1.0]."""
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number, got {raw!r}")
    if not 0.0 <= value <= 1.0:
        raise argparse.ArgumentTypeError(
            f"must be between 0.0 and 1.0 (confidence is a probability), got {value}"
        )
    return value


def _resolve_directory(raw: str, *, label: str) -> Path | None:
    """Resolve *raw* to an existing directory, or report why it cannot be used."""
    try:
        target = Path(raw).expanduser()
    except (RuntimeError, ValueError) as exc:  # e.g. bad ~user expansion
        _err(f"{label} path {raw!r} is invalid: {exc}")
        return None
    try:
        target = target.resolve()
    except OSError as exc:
        _err(f"could not resolve {label} path {raw!r}: {exc}")
        return None
    if not target.exists():
        _err(f"{label} path does not exist: {target}")
        return None
    if not target.is_dir():
        _err(f"{label} path is not a directory: {target}")
        return None
    return target


def _write_or_print(rendered: str, output: str | None) -> int:
    """Emit *rendered* to *output* (a file) or stdout. Returns an exit code."""
    if output:
        output_path = Path(output).expanduser()
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            _err(f"could not write output to {output_path}: {exc.strerror or exc}")
            return EXIT_ERROR
        return EXIT_OK
    print(rendered)
    return EXIT_OK


def _run_scan(args: argparse.Namespace) -> int:
    target = _resolve_directory(args.target, label="scan target")
    if target is None:
        return EXIT_ERROR

    payload = build_scan_payload(target, min_confidence=args.min_confidence)
    code = _write_or_print(json.dumps(payload, indent=2), args.output)
    if code != EXIT_OK:
        return code

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        breached = any(
            SEVERITY_ORDER.get(str(finding["severity"]), 0) >= threshold
            for finding in payload["findings"]
        )
        if breached:
            return EXIT_POLICY
    return EXIT_OK


def _load_payload(findings_file: str) -> dict[str, object] | None:
    """Read and validate a scan payload, reporting clear errors on failure."""
    path = Path(findings_file).expanduser()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        _err(f"findings file not found: {path}")
        return None
    except IsADirectoryError:
        _err(f"findings file is a directory, expected a JSON file: {path}")
        return None
    except OSError as exc:
        _err(f"could not read findings file {path}: {exc.strerror or exc}")
        return None
    except UnicodeDecodeError:
        _err(f"findings file is not valid UTF-8 text: {path}")
        return None

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        _err(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})")
        return None

    if not isinstance(payload, dict):
        _err(
            f"{path} must contain a JSON object produced by 'aive scan', "
            f"got a {type(payload).__name__}"
        )
        return None
    return payload


def _run_plan(args: argparse.Namespace) -> int:
    payload = _load_payload(args.findings_file)
    if payload is None:
        return EXIT_ERROR
    try:
        rendered = build_patch_plan_markdown(payload)
    except (TypeError, KeyError, ValueError) as exc:
        _err(
            f"{args.findings_file} is not a valid scan payload "
            f"(is it the output of 'aive scan'?): {exc}"
        )
        return EXIT_ERROR
    return _write_or_print(rendered, args.output)


def _run_verify(args: argparse.Namespace) -> int:
    target = _resolve_directory(args.target, label="verify target")
    if target is None:
        return EXIT_ERROR

    checks = run_verification(target)
    if args.json:
        print(json.dumps([check.to_dict() for check in checks], indent=2))
    else:
        palette = Palette(should_use_color(sys.stdout, no_color=args.no_color))
        for check in checks:
            print(f"- {check.name}: {palette.status(check.status)} ({check.details})")
    failed = any(check.status == "fail" for check in checks)
    return EXIT_POLICY if args.strict and failed else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aive", description="AIVE exploit-to-patch toolkit.")
    parser.add_argument("--version", action="version", version=f"aive {__version__}")
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour in terminal output (also honours NO_COLOR).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository and emit a findings payload.")
    scan.add_argument("target", nargs="?", default=".", help="Repository path to scan.")
    scan.add_argument("--output", help="Optional file to write JSON payload to.")
    scan.add_argument(
        "--min-confidence",
        type=_confidence,
        default=0.0,
        metavar="0.0-1.0",
        help="Drop findings below this confidence (0.0-1.0).",
    )
    scan.add_argument("--fail-on", choices=SEVERITY_CHOICES, help="Exit non-zero at this severity or higher.")
    scan.set_defaults(func=_run_scan)

    plan = sub.add_parser("plan", help="Render a patch plan from a findings payload.")
    plan.add_argument("findings_file", help="Path to the JSON payload generated by scan.")
    plan.add_argument("--output", help="Optional file to write markdown output to.")
    plan.set_defaults(func=_run_plan)

    verify = sub.add_parser("verify", help="Run lightweight verification checks.")
    verify.add_argument("target", nargs="?", default=".", help="Repository path to verify.")
    verify.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    verify.add_argument("--strict", action="store_true", help="Exit non-zero when any check fails.")
    verify.set_defaults(func=_run_verify)

    return parser


def _silence_stdout() -> None:
    """Redirect stdout to devnull so interpreter shutdown does not re-raise EPIPE."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Global flags live on the top-level parser; ensure subcommand handlers can
    # always read them even if argparse did not set the attribute.
    if not hasattr(args, "no_color"):
        args.no_color = False
    try:
        return int(args.func(args))
    except BrokenPipeError:
        # A downstream reader closed the pipe (e.g. `aive scan . | head`).
        # Silence the follow-up flush error by redirecting stdout to devnull,
        # then exit with the conventional 128 + SIGPIPE(13) status.
        _silence_stdout()
        return 141
    except KeyboardInterrupt:
        print("aive: interrupted", file=sys.stderr)
        return 130
    except OSError as exc:
        if exc.errno == errno.EPIPE:
            _silence_stdout()
            return 141
        _err(str(exc.strerror or exc))
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
