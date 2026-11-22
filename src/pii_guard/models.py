"""Core data models for Zero-Trust DLP findings and scan reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Risk severity levels ordered from lowest to highest."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]


@dataclass(frozen=True)
class Finding:
    """Represents a single sensitive data leak detected in text or image OCR."""

    rule_id: str
    category: str
    severity: Severity
    description: str
    masked_match: str
    source: str
    line: int
    start: int
    end: int

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


@dataclass
class ScanReport:
    """Aggregated DLP findings across one or more scanned targets."""

    targets: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        return any(f.severity.rank >= threshold.rank for f in self.findings)

    def summary_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": self.targets,
            "total_findings": self.total_findings,
            "summary": self.summary_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }
