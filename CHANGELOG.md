# Changelog

All notable changes to AIVE are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
honor [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Packaging metadata for distribution: `[project.urls]`, an expanded classifier
  and keyword set, a `py.typed` typing marker, and a validated sdist/wheel build
  (`python -m build`, `twine check` clean).
- One-line install path via `pipx`/`pip install git+…` and status badges in the
  README.
- `CHANGELOG.md`, `CONTRIBUTING.md`, and a Homebrew formula template under
  `packaging/homebrew/`.

## [0.2.0] - 2026

### Added
- Unified `aive` command wrapping the three loop stages (`scan`, `plan`,
  `verify`) as a proper console entry point.
- Confidence, severity, and blast-radius scoring on every finding, sorted
  worst-first.
- Inline suppression via `# aive: ignore`.
- CI gating flags: `--fail-on` and `--min-confidence`.
- Eight-rule pattern scanner (dynamic exec, `shell=True`, `os.system`, unsafe
  deserialization, `yaml.load`, hard-coded credentials, disabled TLS
  verification, weak hashing).
- GitHub Actions dry-run workflow.

[Unreleased]: https://github.com/waleedsworld/aive-protocol/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/waleedsworld/aive-protocol/releases/tag/v0.2.0
