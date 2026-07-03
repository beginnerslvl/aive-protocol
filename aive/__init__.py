from .diff import (
    build_diff_markdown,
    build_diff_payload,
    compute_diff,
    finding_fingerprint,
)
from .engine import (
    RULES,
    build_patch_plan_markdown,
    build_scan_payload,
    patch_options_for,
    run_verification,
    scan_repository,
    summarize_severity,
)

__version__ = "0.2.0"

__all__ = [
    "RULES",
    "build_diff_markdown",
    "build_diff_payload",
    "build_patch_plan_markdown",
    "build_scan_payload",
    "compute_diff",
    "finding_fingerprint",
    "patch_options_for",
    "run_verification",
    "scan_repository",
    "summarize_severity",
    "__version__",
]
