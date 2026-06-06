"""Enable ``python -m aive`` as an alias for the ``aive`` console script.

The console entry point declared in ``pyproject.toml`` requires the package to
be installed. Providing a module entry point means the CLI is also runnable
straight from a source checkout (``python -m aive scan .``), which keeps
end-to-end tests independent of whether the console script is on ``PATH``.
"""
from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
