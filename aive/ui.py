"""Rich terminal rendering for the AIVE toolkit.

The core library stays zero-dependency: ``scan``/``plan``/``verify`` emit the
same JSON and plain text they always have, so pipelines and CI gating are
untouched. This module is the *presentation* layer that lights up when a human
is at the keyboard. It renders findings as colour-graded tables, drives the
scan behind a live progress bar, and hosts an interactive menu.

Everything degrades gracefully: if `rich` is not installed the helpers fall
back to plain ``print`` so ``--pretty`` and ``aive tui`` still work (just
without the paint). Detection is centralised in :data:`RICH_AVAILABLE`.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

try:  # rich is an optional extra: `pip install "aive-protocol[ui]"`
    from rich.align import Align
    from rich.box import HEAVY_HEAD, ROUNDED
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.prompt import Prompt
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only without rich installed
    RICH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Palette + small helpers
# ---------------------------------------------------------------------------

SEVERITY_STYLE = {
    "high": "bold white on red",
    "medium": "bold black on yellow",
    "low": "bold black on cyan",
}
SEVERITY_ACCENT = {"high": "red", "medium": "yellow", "low": "cyan"}
STATUS_GLYPH = {"pass": ("✓", "bold green"), "warn": ("!", "bold yellow"), "fail": ("✗", "bold red")}

_BANNER = r"""
   █████╗ ██╗██╗   ██╗███████╗
  ██╔══██╗██║██║   ██║██╔════╝
  ███████║██║██║   ██║█████╗
  ██╔══██║██║╚██╗ ██╔╝██╔══╝
  ██║  ██║██║ ╚████╔╝ ███████╗
  ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝
""".strip("\n")


def get_console() -> "Console | None":
    """Return a shared Console, or None when rich is unavailable."""
    if not RICH_AVAILABLE:
        return None
    return Console(highlight=False)


def _confidence_bar(confidence: float) -> "Text":
    filled = round(confidence * 10)
    accent = "green" if confidence >= 0.85 else "yellow" if confidence >= 0.7 else "red"
    bar = Text()
    bar.append("█" * filled, style=accent)
    bar.append("░" * (10 - filled), style="grey37")
    bar.append(f" {confidence:.2f}", style="dim")
    return bar


# ---------------------------------------------------------------------------
# Banner / headers
# ---------------------------------------------------------------------------

def print_banner(console: "Console", subtitle: str = "exploit-to-patch, before red-team automation gets there first") -> None:
    logo = Text(_BANNER, style="bold cyan")
    tagline = Text("AI-Validated Exploit", style="bold white")
    sub = Text(subtitle, style="dim italic")
    body = Group(Align.center(logo), Align.center(tagline), Align.center(sub))
    console.print(Panel(body, box=ROUNDED, border_style="cyan", padding=(1, 4)))


# ---------------------------------------------------------------------------
# Scan rendering
# ---------------------------------------------------------------------------

def render_scan_payload(console: "Console | None", payload: dict[str, Any]) -> None:
    """Render a scan payload as a coloured summary + findings table."""
    if console is None:
        _plain_scan(payload)
        return

    summary = payload.get("severity_summary", {})
    count = payload.get("finding_count", 0)
    repo = payload.get("repo", "unknown")

    chips = Text()
    chips.append(f"  repo ", style="dim")
    chips.append(f" {repo} ", style="bold white on grey23")
    chips.append("    ")
    for sev in ("high", "medium", "low"):
        n = summary.get(sev, 0)
        style = SEVERITY_STYLE[sev] if n else "dim"
        chips.append(f" {sev}:{n} ", style=style)
        chips.append(" ")

    if count == 0:
        console.print(
            Panel(
                Align.center(Text("✓  Clean scan — no high-signal findings", style="bold green")),
                title="AIVE scan", border_style="green", box=ROUNDED, padding=(1, 2),
            )
        )
        console.print(chips)
        return

    console.print(Panel(chips, title="AIVE scan", border_style="cyan", box=ROUNDED, padding=(0, 1)))

    table = Table(box=HEAVY_HEAD, header_style="bold cyan", expand=True, show_lines=False, border_style="grey37")
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Sev", justify="center", width=8)
    table.add_column("Rule", style="bold", no_wrap=True)
    table.add_column("Location", style="cyan", no_wrap=True)
    table.add_column("Confidence", width=18)
    table.add_column("Blast", justify="center")
    table.add_column("Finding")

    blast_style = {"broad": "bold red", "moderate": "yellow", "localized": "green"}
    for i, f in enumerate(payload.get("findings", []), start=1):
        sev = str(f.get("severity", "low"))
        blast = str(f.get("blast_radius", "localized"))
        table.add_row(
            str(i),
            Text(f" {sev} ", style=SEVERITY_STYLE.get(sev, "white")),
            f.get("rule_id", ""),
            f"{f.get('file_path','')}:{f.get('line','')}",
            _confidence_bar(float(f.get("confidence", 0.0))),
            Text(blast, style=blast_style.get(blast, "white")),
            Text(str(f.get("title", "")), style="white"),
        )
    console.print(table)
    console.print(chips)


def _plain_scan(payload: dict[str, Any]) -> None:
    summary = payload.get("severity_summary", {})
    print("AIVE scan —", payload.get("repo", "unknown"))
    print(f"  findings: {payload.get('finding_count', 0)}  "
          f"(high:{summary.get('high',0)} medium:{summary.get('medium',0)} low:{summary.get('low',0)})")
    for i, f in enumerate(payload.get("findings", []), start=1):
        print(f"  {i:>2}. [{f.get('severity','')}] {f.get('rule_id','')} "
              f"{f.get('file_path','')}:{f.get('line','')} "
              f"(conf {float(f.get('confidence',0)):.2f}, {f.get('blast_radius','')}) — {f.get('title','')}")


# ---------------------------------------------------------------------------
# Verify rendering
# ---------------------------------------------------------------------------

def render_verification(console: "Console | None", checks: list[dict[str, Any]]) -> None:
    if console is None:
        for c in checks:
            print(f"- {c['name']}: {c['status']} ({c['details']})")
        return

    table = Table(box=ROUNDED, header_style="bold cyan", expand=True, border_style="grey37")
    table.add_column("", justify="center", width=3)
    table.add_column("Check", style="bold", no_wrap=True)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Details", style="dim")

    for c in checks:
        glyph, style = STATUS_GLYPH.get(c["status"], ("?", "white"))
        table.add_row(
            Text(glyph, style=style),
            str(c["name"]),
            Text(str(c["status"]).upper(), style=style),
            str(c["details"]),
        )

    failed = sum(1 for c in checks if c["status"] == "fail")
    warned = sum(1 for c in checks if c["status"] == "warn")
    if failed:
        border, verdict = "red", Text("✗  verification failed", style="bold red")
    elif warned:
        border, verdict = "yellow", Text("!  passed with warnings", style="bold yellow")
    else:
        border, verdict = "green", Text("✓  all checks passed", style="bold green")

    console.print(Panel(table, title="AIVE verify", border_style=border, box=ROUNDED, padding=(0, 1)))
    console.print(Align.center(verdict))


# ---------------------------------------------------------------------------
# Progress-driven scan (used by TUI and --pretty)
# ---------------------------------------------------------------------------

def scan_with_progress(console: "Console | None", target: Path, min_confidence: float, builder: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    """Run the scan while showing a live progress bar. Falls back to a plain call."""
    if console is None or not RICH_AVAILABLE:
        return builder(target, min_confidence=min_confidence)

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None, complete_style="cyan", finished_style="green"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"scanning {target.name}", total=100)
        for step in (25, 55, 80):
            progress.update(task, completed=step)
            time.sleep(0.05)
        payload = builder(target, min_confidence=min_confidence)
        progress.update(task, completed=100, description="scan complete")
        time.sleep(0.05)
    return payload


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def run_interactive_menu(
    default_target: str,
    scan_builder: Callable[..., dict[str, Any]],
    verifier: Callable[[Path], list[Any]],
    plan_builder: Callable[[dict[str, Any]], str],
) -> int:
    """Interactive TUI menu. Uses rich when available, else a plain loop."""
    console = get_console()
    if console is None:
        return _plain_menu(default_target, scan_builder, verifier, plan_builder)

    print_banner(console)
    last_payload: dict[str, Any] | None = None

    menu = Table.grid(padding=(0, 2))
    menu.add_column(style="bold cyan", justify="right")
    menu.add_column(style="white")
    menu.add_row("1", "Scan a repository for risky patterns")
    menu.add_row("2", "Verify repo hygiene (syntax / tests / CI)")
    menu.add_row("3", "Draft a patch plan from the last scan")
    menu.add_row("4", "Show findings from the last scan")
    menu.add_row("q", "Quit")

    while True:
        console.print(Panel(menu, title="What next?", border_style="cyan", box=ROUNDED, padding=(1, 2)))
        choice = Prompt.ask("[bold cyan]aive[/]", choices=["1", "2", "3", "4", "q"], default="1")

        if choice == "q":
            console.print(Align.center(Text("stay safe out there ✦", style="dim italic")))
            return 0

        if choice == "1":
            target = Prompt.ask("  target path", default=default_target)
            raw = Prompt.ask("  min confidence", default="0.0")
            try:
                min_conf = float(raw)
            except ValueError:
                min_conf = 0.0
            path = Path(target).resolve()
            last_payload = scan_with_progress(console, path, min_conf, scan_builder)
            render_scan_payload(console, last_payload)

        elif choice == "2":
            target = Prompt.ask("  target path", default=default_target)
            checks = verifier(Path(target).resolve())
            render_verification(console, [c.to_dict() for c in checks])

        elif choice == "3":
            if not last_payload:
                console.print(Text("  run a scan first (option 1)", style="yellow"))
                continue
            markdown = plan_builder(last_payload)
            try:
                from rich.markdown import Markdown

                console.print(Panel(Markdown(markdown), title="patch plan", border_style="cyan", box=ROUNDED))
            except Exception:
                console.print(markdown)

        elif choice == "4":
            if not last_payload:
                console.print(Text("  run a scan first (option 1)", style="yellow"))
                continue
            render_scan_payload(console, last_payload)

        console.print(Rule(style="grey30"))


def _plain_menu(default_target, scan_builder, verifier, plan_builder) -> int:
    last_payload: dict[str, Any] | None = None
    print("AIVE interactive (plain mode — install 'rich' for the full TUI)")
    while True:
        print("\n[1] scan  [2] verify  [3] plan  [4] show findings  [q] quit")
        choice = input("aive> ").strip().lower()
        if choice == "q":
            return 0
        if choice == "1":
            target = input("target path [.]: ").strip() or default_target
            last_payload = scan_builder(Path(target).resolve(), min_confidence=0.0)
            _plain_scan(last_payload)
        elif choice == "2":
            target = input("target path [.]: ").strip() or default_target
            checks = verifier(Path(target).resolve())
            for c in checks:
                print(f"- {c.name}: {c.status} ({c.details})")
        elif choice == "3":
            if not last_payload:
                print("run a scan first")
                continue
            print(plan_builder(last_payload))
        elif choice == "4":
            if not last_payload:
                print("run a scan first")
                continue
            _plain_scan(last_payload)
        else:
            print("unknown option")
