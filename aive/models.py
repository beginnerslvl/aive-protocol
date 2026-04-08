from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    file_path: str
    line: int
    severity: str
    confidence: float
    snippet: str
    blast_radius: str
    exploit_hypothesis: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class PatchOption:
    title: str
    summary: str
    safety_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class VerificationCheck:
    name: str
    status: str
    details: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
