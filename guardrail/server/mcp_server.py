"""Model Context Protocol (MCP) Server for GuardRail-Agent.

Exposes native MCP tools allowing AI agents (Claude Code, Cursor, Windsurf, Aider)
to self-audit proposed dependencies, code diffs, and architectural boundaries
before writing files or committing changes ("Shift-Left" pair-programming guard).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from mcp.server.mcpserver import MCPServer as _ServerClass
except ImportError:
    import importlib
    _ServerClass = getattr(importlib.import_module("mcp.server.fastmcp"), "FastMCP")

mcp = _ServerClass("guardrail")

from guardrail.analyzers.architecture import ArchitectureAnalyzer
from guardrail.analyzers.bypasses import BypassesAnalyzer
from guardrail.analyzers.slopsquatting import check_dependencies_async
from guardrail.cli import execute_scan
from guardrail.config import load_config
from guardrail.git_diff import (
    DependencyChange,
    extract_dependencies_from_pyproject_toml,
    extract_package_from_requirement_line,
    get_git_diff,
)
from guardrail.models import Severity


@mcp.tool()
async def verify_dependencies(
    manifest_content: str,
    manifest_type: str = "requirements.txt",
) -> str:
    """
    Asynchronously audit proposed dependencies for hallucinated packages (slopsquatting),
    brand-new packages (< 30 days old), and typosquatting attacks.

    Args:
        manifest_content: Full text or diff of requirements.txt or pyproject.toml.
        manifest_type: Manifest format: 'requirements.txt' or 'pyproject.toml'.
    """
    cfg = load_config()
    deps: List[DependencyChange] = []
    seen: set[str] = set()

    m_type = manifest_type.lower()
    if "pyproject" in m_type or "[project" in manifest_content:
        # Try TOML parsing
        toml_deps = extract_dependencies_from_pyproject_toml(manifest_content, "pyproject.toml")
        for td in toml_deps:
            if td.package_name not in seen:
                seen.add(td.package_name)
                deps.append(td)

    # If requirements format or pyproject had simple lines / diff hunks
    if not deps:
        for idx, line in enumerate(manifest_content.splitlines()):
            clean_line = line.lstrip("+").strip()
            res = extract_package_from_requirement_line(clean_line)
            if res:
                pkg, spec = res
                if pkg not in seen:
                    seen.add(pkg)
                    deps.append(
                        DependencyChange(
                            package_name=pkg,
                            specifier=spec,
                            source_file="manifest",
                            line_number=idx + 1,
                        )
                    )

    if not deps:
        return json.dumps(
            {
                "status": "passed",
                "message": "No package dependencies found in the provided manifest content.",
                "total_checked": 0,
                "verified_packages": [],
                "findings": [],
            },
            indent=2,
        )

    findings = await check_dependencies_async(deps, cfg.slopsquatting)

    hallucinated = [f.details.get("package", "") for f in findings if f.rule_id == "GUARD-SLOP-001"]
    blocklisted = [f.details.get("package", "") for f in findings if f.rule_id == "GUARD-SLOP-000"]
    newly_registered = [
        {"package": f.details.get("package"), "age_days": f.details.get("age_days")}
        for f in findings
        if f.rule_id == "GUARD-SLOP-002"
    ]
    typosquats = [
        {"package": f.details.get("package"), "similar_to": f.details.get("similar_to")}
        for f in findings
        if f.rule_id == "GUARD-SLOP-003"
    ]

    failed_pkgs = set(hallucinated) | set(blocklisted)
    verified = [d.package_name for d in deps if d.package_name not in failed_pkgs]

    has_errors = any(f.severity == Severity.ERROR for f in findings)
    status = "failed" if has_errors else "passed"

    recommendations: List[str] = []
    if hallucinated:
        recommendations.append(
            f"REMOVE hallucinated dependencies: {hallucinated}. These packages do NOT exist on PyPI and represent severe slopsquatting risks."
        )
    if newly_registered:
        recommendations.append(
            f"VERIFY newly registered dependencies: {[p['package'] for p in newly_registered]}. Ensure they are authentic and not malicious typosquats."
        )
    if typosquats:
        recommendations.append(
            f"CHECK potential typosquats: {[t['package'] for t in typosquats]} against legitimate popular alternatives."
        )

    result = {
        "status": status,
        "total_checked": len(deps),
        "verified_packages": verified,
        "hallucinated_packages": hallucinated,
        "blocklisted_packages": blocklisted,
        "newly_registered_packages": newly_registered,
        "typosquat_alerts": typosquats,
        "recommendations": recommendations,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "package": f.details.get("package"),
            }
            for f in findings
        ],
    }
    return json.dumps(result, indent=2)


@mcp.tool()
def audit_code_drift(file_path: str, source_code: str) -> str:
    """
    Run Tree-sitter architectural layer boundary checks and security bypass audits
    against proposed code before writing it to disk or committing.

    Args:
        file_path: Relative or absolute path of the target file (e.g. 'app/domain/user.py').
        source_code: Proposed source code content.
    """
    cfg = load_config()
    code_bytes = source_code.encode("utf-8")

    arch_analyzer = ArchitectureAnalyzer(cfg.architecture)
    bypasses_analyzer = BypassesAnalyzer(cfg.bypasses)

    detected_layer = arch_analyzer.determine_layer(file_path)
    arch_findings = arch_analyzer.analyze_file(file_path, code_bytes)
    bypass_findings = bypasses_analyzer.analyze_file(file_path, source_code)

    all_findings = arch_findings + bypass_findings

    arch_violations = [
        {
            "rule_id": f.rule_id,
            "line": f.line_number,
            "message": f.message,
            "snippet": f.snippet,
        }
        for f in arch_findings
    ]

    linter_suppressions = [
        {
            "rule_id": f.rule_id,
            "line": f.line_number,
            "suppression": f.details.get("suppression"),
            "snippet": f.snippet,
        }
        for f in bypass_findings
        if f.rule_id == "GUARD-BYPASS-001"
    ]

    dangerous_calls = [
        {
            "rule_id": f.rule_id,
            "line": f.line_number,
            "pattern": f.details.get("pattern") or f.details.get("function") or f.details.get("argument"),
            "message": f.message,
            "snippet": f.snippet,
        }
        for f in bypass_findings
        if f.rule_id != "GUARD-BYPASS-001"
    ]

    errors_count = sum(1 for f in all_findings if f.severity == Severity.ERROR)
    warnings_count = sum(1 for f in all_findings if f.severity == Severity.WARNING)

    status = "failed" if errors_count > 0 else "passed"

    recommendations: List[str] = []
    if arch_violations:
        recommendations.append(
            f"Fix architectural boundary violations: File '{file_path}' in layer '{detected_layer}' violates layer import restrictions."
        )
    if linter_suppressions:
        recommendations.append(
            "Remove inline linter suppressions (# noqa, # type: ignore). Resolve the root type/lint errors instead."
        )
    if dangerous_calls:
        recommendations.append(
            "Eliminate dangerous security calls (verify=False, shell=True, eval/exec). Use secure APIs."
        )

    result = {
        "status": status,
        "file_path": file_path,
        "detected_layer": detected_layer or "none",
        "errors": errors_count,
        "warnings": warnings_count,
        "architectural_violations": arch_violations,
        "linter_suppressions": linter_suppressions,
        "dangerous_calls": dangerous_calls,
        "recommendations": recommendations,
    }
    return json.dumps(result, indent=2)


@mcp.tool()
async def scan_current_git_diff() -> str:
    """
    Run an audit across all uncommitted working tree modifications in the local git repository.
    Verifies new dependencies, architectural import changes, and security bypasses.
    """
    cfg = load_config()
    cwd = Path.cwd()
    diff_result = get_git_diff(staged=False, cwd=cwd)

    if not diff_result.files and not diff_result.new_dependencies:
        return json.dumps(
            {
                "verdict": "PASSED",
                "message": "No uncommitted modifications found in the current working directory.",
                "total_files_modified": 0,
                "total_violations": 0,
                "recommendations": [],
            },
            indent=2,
        )

    summary = await execute_scan(cfg, cwd, diff_result=diff_result)
    is_failed = summary.has_failures(cfg.general.fail_on_severity)

    recommendations: List[str] = []
    if is_failed:
        recommendations.append(
            "Quality gate failed: Resolve the identified drift violations before committing."
        )
    else:
        recommendations.append("All uncommitted changes comply with drift guardrails.")

    result = {
        "verdict": "FAILED" if is_failed else "PASSED",
        "total_files_modified": len(diff_result.files),
        "total_violations": summary.total_violations,
        "errors": summary.errors_count,
        "warnings": summary.warnings_count,
        "recommendations": recommendations,
        "violations": [
            {
                "rule_id": f.rule_id,
                "analyzer": f.analyzer,
                "severity": f.severity.value,
                "message": f.message,
                "file": f.file_path,
                "line": f.line_number,
                "snippet": f.snippet,
            }
            for f in summary.findings
        ],
    }
    return json.dumps(result, indent=2)


def main() -> None:
    """Entry point for the standalone guardrail-mcp executable."""
    mcp.run()


if __name__ == "__main__":
    main()
