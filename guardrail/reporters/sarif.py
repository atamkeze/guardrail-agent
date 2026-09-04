"""SARIF (Static Analysis Results Interchange Format) exporter for GuardRail-Agent.

Enables seamless integration with GitHub Advanced Security code scanning,
GitLab SAST, and Azure DevOps pull request annotations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from guardrail.models import Finding, ScanSummary, Severity


RULE_DEFINITIONS: Dict[str, Dict[str, str]] = {
    "GUARD-SLOP-000": {
        "name": "BlocklistedDependency",
        "short": "Dependency explicitly blocklisted by security policy",
        "description": "The introduced package is blocked by organizational policy.",
    },
    "GUARD-SLOP-001": {
        "name": "HallucinatedPackage",
        "short": "Hallucinated dependency does not exist in registry (Slopsquatting risk)",
        "description": "AI coding assistants frequently hallucinate packages. Malicious actors register these names to deliver malware.",
    },
    "GUARD-SLOP-002": {
        "name": "NewlyRegisteredPackage",
        "short": "Suspicious newly-registered dependency",
        "description": "Package was registered very recently, carrying elevated supply-chain takeover risk.",
    },
    "GUARD-SLOP-003": {
        "name": "TyposquattedDependency",
        "short": "Dependency name is suspiciously similar to a popular package",
        "description": "High likelihood of accidental typosquatting or hallucinated typo package.",
    },
    "GUARD-ARCH-001": {
        "name": "LayerBoundaryViolation",
        "short": "Architectural layer boundary violation",
        "description": "An architectural layer imported a forbidden layer, causing architectural erosion.",
    },
    "GUARD-ARCH-002": {
        "name": "ForbiddenModuleImport",
        "short": "Forbidden module imported in architectural layer",
        "description": "A module restricted by layer isolation policy was imported.",
    },
    "GUARD-BYPASS-001": {
        "name": "LinterSuppressionBypass",
        "short": "Linter or typechecker suppression detected in AI changes",
        "description": "AI agent added inline linter suppressions (# noqa, # type: ignore) instead of fixing issues.",
    },
    "GUARD-SEC-001": {
        "name": "TlsVerificationDisabled",
        "short": "TLS/SSL certificate verification disabled (verify=False)",
        "description": "Disabling TLS verification exposes the application to man-in-the-middle attacks.",
    },
    "GUARD-SEC-002": {
        "name": "SubprocessShellInjection",
        "short": "Subprocess shell=True command injection risk",
        "description": "Executing commands with shell=True allows arbitrary shell injection.",
    },
    "GUARD-SEC-003": {
        "name": "DynamicCodeExecution",
        "short": "Arbitrary code execution via eval() or exec()",
        "description": "eval() and exec() allow arbitrary remote code execution if evaluating untrusted input.",
    },
    "GUARD-SEC-004": {
        "name": "InsecureOsSystem",
        "short": "Use of os.system() is discouraged",
        "description": "os.system() is vulnerable to shell metacharacter injections.",
    },
}


def severity_to_sarif_level(severity: Severity) -> str:
    """Map GuardRail severity to SARIF level."""
    if severity == Severity.ERROR:
        return "error"
    elif severity == Severity.WARNING:
        return "warning"
    return "note"


def generate_sarif_report(summary: ScanSummary) -> Dict[str, Any]:
    """Generate a valid SARIF v2.1.0 dictionary from a ScanSummary."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for finding in summary.findings:
        rule_meta = RULE_DEFINITIONS.get(
            finding.rule_id,
            {
                "name": finding.rule_id.replace("-", "_"),
                "short": finding.message[:100],
                "description": finding.message,
            },
        )

        if finding.rule_id not in rules_map:
            rules_map[finding.rule_id] = {
                "id": finding.rule_id,
                "name": rule_meta["name"],
                "shortDescription": {"text": rule_meta["short"]},
                "fullDescription": {"text": rule_meta["description"]},
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(finding.severity)
                },
                "properties": {
                    "tags": ["security", "ai-drift", finding.analyzer]
                },
            }

        start_line = finding.line_number if finding.line_number and finding.line_number > 0 else 1
        start_col = (finding.column + 1) if finding.column is not None and finding.column >= 0 else 1

        sarif_result: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": severity_to_sarif_level(finding.severity),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_col,
                        },
                    }
                }
            ],
        }

        if finding.snippet:
            sarif_result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.snippet
            }

        sarif_results.append(sarif_result)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GuardRail-Agent",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/guardrail-agent/guardrail-agent",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return sarif_doc


def write_sarif_file(summary: ScanSummary, output_path: Path | str) -> None:
    """Write the SARIF report to a file path."""
    sarif_data = generate_sarif_report(summary)
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)
