# Contributing to AIVE

Thanks for wanting to make AIVE better. It's a small, dependency-free prototype,
so contributing is deliberately low-ceremony.

## Getting set up

```bash
git clone https://github.com/waleedsworld/aive-protocol.git
cd aive-protocol
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running the checks

The whole suite is standard-library `unittest` — no extra services:

```bash
python -m unittest discover -s tests
# or, with the dev extras installed:
pytest
```

AIVE scans itself in CI, so run it against its own tree before opening a PR:

```bash
aive scan . --fail-on high
aive verify . --strict
```

## Adding a scanner rule

Rules live together on purpose. To add one:

1. Add a pattern entry to `RULES` in `aive/engine.py`.
2. Add the matching remediation to `SPECIFIC_PATCH_OPTIONS` right beside it.
3. Cover it with a test in `tests/`.

Give the rule a stable ID (`AIVE-PY-00N` for Python, `AIVE-SEC-00N` for
cross-cutting security patterns) and document it in the README rule-set table.

## Pull requests

- Keep changes focused and describe the motivation in the PR body.
- Make sure `unittest`/`pytest` passes and a self-scan stays clean
  (use `# aive: ignore` with a short justification for any intentional pattern).
- No new runtime dependencies — the zero-dependency guarantee is a feature.

## Reporting issues

Open a GitHub issue with a minimal reproduction: the command you ran, what you
expected, and what happened. Security-sensitive reports can note that in the
title so they get triaged first.

By contributing you agree that your work is licensed under the project's
[MIT License](LICENSE).
