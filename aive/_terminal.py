"""Terminal-awareness helpers for the AIVE command-line interface.

Kept deliberately dependency-free so the CLI stays install-light. The helpers
answer three questions that a well-behaved terminal program should ask before
it writes anything:

* Is the output going to a real terminal, or is it being piped/redirected?
* Should ANSI colour be emitted (respecting ``NO_COLOR`` / ``FORCE_COLOR`` and
  an explicit ``--no-color`` flag)?
* How wide is the terminal, so long lines can be wrapped instead of overflowing?

Every function degrades gracefully: when stdout is not a TTY, when the
environment lies about a terminal, or when ``os.get_terminal_size`` is
unavailable (a common situation under CI and piped output), the safe,
plain-text answer is returned.
"""
from __future__ import annotations

import os
import shutil
import sys
from typing import IO

# ANSI SGR codes, applied only when colour is enabled.
_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
}

# Default when a terminal size cannot be determined (piped output, CI, etc.).
_DEFAULT_WIDTH = 80
_MIN_WIDTH = 20


def _stream_is_tty(stream: IO[str] | None) -> bool:
    """Return True only when *stream* is a real, interactive terminal."""
    if stream is None:
        return False
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return False
    try:
        return bool(isatty())
    except (ValueError, OSError):
        # ValueError: I/O operation on closed file; OSError: detached stream.
        return False


def should_use_color(stream: IO[str] | None = None, *, no_color: bool = False) -> bool:
    """Decide whether ANSI colour should be written to *stream*.

    Resolution order (first match wins):

    1. An explicit ``--no-color`` request always disables colour.
    2. ``NO_COLOR`` set (to any value) disables colour -- see no-color.org.
    3. ``FORCE_COLOR`` set to a non-empty, non-"0" value forces colour on.
    4. Otherwise, colour is used only when *stream* is an interactive TTY.
    """
    if no_color:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    force = os.environ.get("FORCE_COLOR")
    if force is not None and force not in ("", "0", "false", "False"):
        return True
    if stream is None:
        stream = sys.stdout
    return _stream_is_tty(stream)


def terminal_width(stream: IO[str] | None = None, *, default: int = _DEFAULT_WIDTH) -> int:
    """Best-effort terminal column count with a sane fallback.

    Honours the ``COLUMNS`` environment variable first (so callers can force a
    width in tests and pipelines), then queries the stream, then the process,
    and finally falls back to *default*. Never raises and never returns an
    absurdly small width.
    """
    columns_env = os.environ.get("COLUMNS")
    if columns_env:
        try:
            return max(_MIN_WIDTH, int(columns_env))
        except ValueError:
            pass

    if stream is not None:
        fileno = getattr(stream, "fileno", None)
        if fileno is not None:
            try:
                size = os.get_terminal_size(fileno())
                if size.columns > 0:
                    return max(_MIN_WIDTH, size.columns)
            except (OSError, ValueError):
                pass

    try:
        columns = shutil.get_terminal_size(fallback=(default, 24)).columns
    except (OSError, ValueError):
        columns = default
    return max(_MIN_WIDTH, columns or default)


class Palette:
    """Small colour helper bound to a single enable/disable decision."""

    __slots__ = ("enabled",)

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        prefix = "".join(_CODES.get(style, "") for style in styles)
        if not prefix:
            return text
        return f"{prefix}{text}{_CODES['reset']}"

    def status(self, status: str) -> str:
        """Colour a verification status token (pass/warn/fail)."""
        colour = {"pass": "green", "warn": "yellow", "fail": "red"}.get(status)
        return self.paint(status, colour) if colour else status
