"""Data models for GuardRail Autonomous Penetration Testing Agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from guardrail.models import Finding, Severity


@dataclass
class CodebaseProfile:
    target_path: str
    languages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    architecture_type: str = "Unknown System"
    entry_points: List[str] = field(default_factory=list)
    database_layer: Optional[str] = None
    auth_mechanism: Optional[str] = None
    external_integrations: List[str] = field(default_factory=list)
    has_payment_processing: bool = False
    has_healthcare_data: bool = False
    has_financial_data: bool = False
    summary: str = ""


@dataclass
class ModuleSelection:
    module_id: str
    name: str
    priority: str  # "MAXIMUM", "HIGH", "MEDIUM", "LOW"
    weight: float
    reason: str
    enabled: bool = True


@dataclass
class ExecutionPlan:
    profile: CodebaseProfile
    selected_modules: List[ModuleSelection] = field(default_factory=list)
    reasoning_narrative: str = ""


@dataclass
class PentestReport:
    repo_name: str
    target_path_or_url: str
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    execution_plan: Optional[ExecutionPlan] = None
    overall_risk_score: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    findings: List[Finding] = field(default_factory=list)
    executive_summary: str = ""
    remediation_recommendations: List[str] = field(default_factory=list)
    pdf_report_path: Optional[str] = None
    duration_seconds: float = 0.0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_or_error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def calculate_risk_score(self) -> str:
        # Check severity breakdown
        errors = self.critical_or_error_count
        warnings = self.warning_count

        # Check for specific high impact findings
        rule_ids = {f.rule_id for f in self.findings}
        has_sqli = any("SQLI" in rid for rid in rule_ids)
        has_cmdi = any("CMDI" in rid for rid in rule_ids)
        has_secrets = any(f.rule_id.startswith("SEC-") for f in self.findings if f.severity == Severity.ERROR)

        if errors >= 3 or has_sqli or has_cmdi or has_secrets:
            self.overall_risk_score = "CRITICAL"
        elif errors >= 1 or warnings >= 5:
            self.overall_risk_score = "HIGH"
        elif warnings >= 2:
            self.overall_risk_score = "MEDIUM"
        elif self.total_findings > 0:
            self.overall_risk_score = "LOW"
        else:
            self.overall_risk_score = "INFORMATIONAL"
        return self.overall_risk_score
