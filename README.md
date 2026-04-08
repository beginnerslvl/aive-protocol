# AIVE

**AI-Validated Exploit**

AIVE is a CVE-like exploit-to-patch loop for AI-operated repositories.

The bet is simple: as coding agents get stronger, the bottleneck shifts from "finding bugs" to proving they are real, estimating blast radius, generating safe patches, running regression checks, and shipping fixes without letting autonomous systems quietly break production.

This repo is a minimal GitHub-first prototype for that idea.

## Why AIVE

- Keep original human code on GitHub as the source of truth.
- Let AI operate inside a constrained maintenance lane.
- Treat exploit discovery as the start of a patch pipeline, not the final output.
- Require cross-checking, verification, and comparable patch options before merge.

## Core Loop

1. Scan a repository for high-risk patterns.
2. Validate whether the issue looks exploitable.
3. Estimate blast radius.
4. Draft multiple safe patch options.
5. Run lightweight regression and workflow checks.
6. Hand off the result to GitHub for review, PRs, and verifier agents.

## What This Prototype Includes

- A lightweight scanner for dangerous code patterns.
- Patch-plan generation built around exploit-to-patch framing.
- Verification checks for syntax, test presence, and workflow hygiene.
- A GitHub Actions dry-run workflow that can be scheduled or triggered manually.

## Repo Layout

```text
.
├── .github/workflows/aive-dry-run.yml
├── aive/
│   ├── __init__.py
│   ├── engine.py
│   └── models.py
├── examples/
│   └── aive-2026-0001.json
├── scripts/
│   ├── patch_plan.py
│   ├── scan_repo.py
│   └── verify_repo.py
├── .gitignore
├── LICENSE
├── pyproject.toml
└── README.md
```

## Quick Start

```bash
python3 scripts/scan_repo.py . --output artifacts/findings.json
python3 scripts/patch_plan.py artifacts/findings.json --output artifacts/patch-plan.md
python3 scripts/verify_repo.py . --json
```

## GitHub Operating Model

The intended production shape is:

- `main` stays human-owned and reviewable.
- AI runs in a sandbox branch or temporary environment.
- one agent proposes patches.
- separate verifier agents reproduce, compare, and cross-check those patches.
- only validated fixes with passing checks are promoted toward merge.

This repo does not claim to solve autonomous code safety end to end. It gives the project a concrete identity, terminology, and a minimal implementation skeleton that can grow into a full GitHub-native patching protocol.

## Example AIVE Record

Example advisory payload: [examples/aive-2026-0001.json](examples/aive-2026-0001.json)

Suggested naming format:

- `AIVE-2026-0001`
- `AIVE-2026-0002`

Each record should represent an issue that has been reproduced, scoped, and paired with at least one safe patch path.

## Roadmap

- GitHub App mode for PR orchestration.
- sandbox execution for AI-generated patches.
- multi-agent verifier quorum before merge.
- regression replay against historical failures.
- blast-radius scoring tied to dependency and ownership graphs.

## Positioning

This is not "AI bug-finding."

It is exploit-to-patch infrastructure for the moment when humans can no longer line-by-line review large volumes of agent-generated code, but still need software that compiles, behaves, and ships safely.
