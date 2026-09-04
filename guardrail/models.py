"""Data models for GuardRail-Agent findings, reports, and rule violations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @classmethod
    def from_str(cls, val: str) -> "Severity":
        val_lower = val.lower()
        if val_lower in ("err", "error", "critical"):
            return cls.ERROR
        if val_lower in ("warn", "warning"):
            return cls.WARNING
        return cls.INFO

    @property
    def level_rank(self) -> int:
        return {"error": 3, "warning": 2, "info": 1}[self.value]


@dataclass
class Finding:
    rule_id: str
    analyzer: str
    severity: Severity
    message: str
    file_path: str
    line_number: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanSummary:
    total_files_scanned: int = 0
    total_violations: int = 0
    errors_count: int = 0
    warnings_count: int = 0
    info_count: int = 0
    findings: List[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.total_violations += 1
        if finding.severity == Severity.ERROR:
            self.errors_count += 1
        elif finding.severity == Severity.WARNING:
            self.warnings_count += 1
        else:
            self.info_count += 1

    def has_failures(self, fail_on_severity: str = "error") -> bool:
        threshold = Severity.from_str(fail_on_severity).level_rank
        for f in self.findings:
            if f.severity.level_rank >= threshold:
                return True
        return False
