"""Shared pytest fixtures for the AIVE test suite."""
from __future__ import annotations

from pathlib import Path

import pytest

# Absolute path to the repository root (parent of the ``tests`` directory).
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo_root() -> Path:
    """The real project checkout, used by smoke tests that scan this repo."""
    return REPO_ROOT


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """A throwaway repository seeded with one finding of each severity tier.

    Returns the path to a temporary directory containing:
      - a high-severity dynamic-exec sink,
      - a medium-severity disabled-TLS-verification call,
      - a low-severity weak-hash call,
      - a clean file with no findings,
      - a ``.gitignore`` so the hygiene check passes.
    """
    (tmp_path / "danger.py").write_text(
        "def run(cmd):\n    return eval(cmd)\n",  # aive: ignore
        encoding="utf-8",
    )
    (tmp_path / "net.py").write_text(
        "import requests\n\nrequests.get(url, verify=False)\n",  # aive: ignore
        encoding="utf-8",
    )
    (tmp_path / "weak.py").write_text(
        "import hashlib\n\ndigest = hashlib.md5(data)\n",  # aive: ignore
        encoding="utf-8",
    )
    (tmp_path / "clean.py").write_text(
        "def add(a, b):\n    return a + b\n",
        encoding="utf-8",
    )
    (tmp_path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    return tmp_path
