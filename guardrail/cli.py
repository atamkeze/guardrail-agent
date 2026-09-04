"""Typer CLI interface for GuardRail-Agent."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import sys
from pathlib import Path
from typing import List, Optional

# Ensure UTF-8 output streams on Windows to prevent charmap UnicodeEncodeErrors
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich.console import Console

from guardrail import __version__
from guardrail.analyzers.architecture import ArchitectureAnalyzer
from guardrail.analyzers.bypasses import BypassesAnalyzer
from guardrail.analyzers.slopsquatting import check_dependencies_async
from guardrail.config import DEFAULT_CONFIG_TOML, GuardrailConfig, load_config
from guardrail.git_diff import (
    DependencyChange,
    DiffResult,
    extract_dependencies_from_diff,
    get_git_diff,
)
from guardrail.models import ScanSummary
from guardrail.reporters.console import render_console_report
from guardrail.reporters.sarif import write_sarif_file

app = typer.Typer(
    name="guardrail",
    help="GuardRail-Agent: AI Codebase Drift & Security Inspection Gate",
    add_completion=False,
)
console = Console(soft_wrap=True)


def is_path_excluded(path_str: str, exclude_patterns: List[str]) -> bool:
    """Check if a path matches any exclusion patterns."""
    norm = path_str.replace("\\", "/").strip("/")
    for pat in exclude_patterns:
        clean = pat.replace("\\", "/").strip("/")
        if fnmatch.fnmatch(norm, clean) or fnmatch.fnmatch(f"/{norm}", clean):
            return True
        pat_dir = clean.rstrip("/*").rstrip("/**")
        if pat_dir and (norm.startswith(f"{pat_dir}/") or f"/{pat_dir}/" in f"/{norm}/"):
            return True
    return False


def collect_project_files(
    root: Path, exclude_patterns: List[str]
) -> List[Path]:
    """Recursively collect all relevant source code files excluding ignored directories."""
    if root.is_file():
        rel_str = root.name
        if not is_path_excluded(rel_str, exclude_patterns):
            return [root]
        return []
    files: List[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel_str = str(p.relative_to(root)).replace("\\", "/")
        if is_path_excluded(rel_str, exclude_patterns):
            continue
        files.append(p)
    return files


async def execute_scan(
    config: GuardrailConfig,
    root: Path,
    diff_result: Optional[DiffResult] = None,
) -> ScanSummary:
    """Run slopsquatting, architecture, and bypasses analyzers."""
    summary = ScanSummary()

    # 1. Slopsquatting check
    deps_to_check: List[DependencyChange] = []
    if diff_result is not None:
        deps_to_check = diff_result.new_dependencies
    else:
        # Full scan: extract from dependency files
        all_files = collect_project_files(root, config.general.exclude_patterns)
        for f in all_files:
            fname = f.name.lower()
            rel_p = str(f.relative_to(root)).replace("\\", "/")
            if fname == "pyproject.toml":
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                    from guardrail.git_diff import extract_dependencies_from_pyproject_toml
                    deps_to_check.extend(extract_dependencies_from_pyproject_toml(content, rel_p))
                except Exception:
                    pass
            elif fname.startswith("requirements") and fname.endswith(".txt"):
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                    from guardrail.git_diff import extract_package_from_requirement_line
                    for idx, line in enumerate(content.splitlines()):
                        res = extract_package_from_requirement_line(line)
                        if res:
                            pkg, spec = res
                            deps_to_check.append(
                                DependencyChange(
                                    package_name=pkg,
                                    specifier=spec,
                                    source_file=rel_p,
                                    line_number=idx + 1,
                                )
                            )
                except Exception:
                    pass

    if deps_to_check and config.slopsquatting.enabled:
        slop_findings = await check_dependencies_async(deps_to_check, config.slopsquatting)
        for sf in slop_findings:
            summary.add_finding(sf)

    # 2. File-level checks (Architecture & Bypasses)
    arch_analyzer = ArchitectureAnalyzer(config.architecture)
    bypasses_analyzer = BypassesAnalyzer(config.bypasses)

    if diff_result is not None:
        # Diff mode: inspect modified files only
        summary.total_files_scanned = len(diff_result.files)
        for rel_path, fdiff in diff_result.files.items():
            if fdiff.status == "deleted":
                continue
            full_path = root / rel_path
            if not full_path.is_file():
                continue
            try:
                code_bytes = full_path.read_bytes()
                code_text = code_bytes.decode("utf-8", errors="replace")

                # Architecture check for python files
                if full_path.suffix == ".py":
                    for f in arch_analyzer.analyze_file(rel_path, code_bytes, diff_result=diff_result):
                        summary.add_finding(f)

                # Bypasses check
                for f in bypasses_analyzer.analyze_file(rel_path, code_text, diff_result=diff_result):
                    summary.add_finding(f)
            except Exception:
                continue
    else:
        # Full scan
        all_files = collect_project_files(root, config.general.exclude_patterns)
        summary.total_files_scanned = len(all_files)
        for full_path in all_files:
            rel_path = (
                full_path.name
                if root.is_file()
                else str(full_path.relative_to(root)).replace("\\", "/")
            )
            try:
                code_bytes = full_path.read_bytes()
                code_text = code_bytes.decode("utf-8", errors="replace")

                if full_path.suffix == ".py":
                    for f in arch_analyzer.analyze_file(rel_path, code_bytes):
                        summary.add_finding(f)

                for f in bypasses_analyzer.analyze_file(rel_path, code_text):
                    summary.add_finding(f)
            except Exception:
                continue

    return summary


@app.command()
def check(
    diff: bool = typer.Option(
        False, "--diff", "-d", help="Inspect only modified files and lines in git diff"
    ),
    staged: bool = typer.Option(
        False, "--staged", "-s", help="Inspect only staged git changes"
    ),
    base_ref: Optional[str] = typer.Option(
        None, "--base-ref", "-b", help="Compare against base git branch or commit (e.g. origin/main, HEAD~1)"
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to custom .drift-rules.toml configuration"
    ),
    sarif: Optional[Path] = typer.Option(
        None, "--sarif", help="File path to write SARIF v2.1.0 report for CI/CD"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output raw JSON scan findings"
    ),
    fail_level: str = typer.Option(
        "error", "--fail-level", help="Minimum severity causing non-zero exit code: error, warning, info"
    ),
) -> None:
    """
    Run GuardRail-Agent inspection. Use --diff or --staged in CI/CD PR checks and git hooks.
    """
    try:
        cfg = load_config(config_file)
    except Exception as exc:
        console.print(f"[bold red]Failed to load configuration:[/bold red] {exc}")
        raise typer.Exit(code=2)

    cwd = Path.cwd()
    diff_result: Optional[DiffResult] = None

    if diff or staged or base_ref:
        diff_result = get_git_diff(staged=staged, base_ref=base_ref, cwd=cwd)
        if not diff_result.files and not diff_result.new_dependencies:
            console.print("[dim]No modified files or dependencies found in git diff.[/dim]")
            raise typer.Exit(code=0)

    summary = asyncio.run(execute_scan(cfg, cwd, diff_result=diff_result))

    if sarif:
        write_sarif_file(summary, sarif)
        console.print(f"[dim]SARIF report exported to {sarif}[/dim]")

    if json_output:
        data = {
            "scanned_files": summary.total_files_scanned,
            "total_violations": summary.total_violations,
            "errors": summary.errors_count,
            "warnings": summary.warnings_count,
            "findings": [
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
        typer.echo(json.dumps(data, indent=2))
    else:
        render_console_report(summary, console=console, fail_on_severity=fail_level)

    if summary.has_failures(fail_level):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Path to file or directory to scan"),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to custom .drift-rules.toml configuration"
    ),
    sarif: Optional[Path] = typer.Option(
        None, "--sarif", help="File path to write SARIF report"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output raw JSON scan findings"
    ),
    fail_level: str = typer.Option(
        "error", "--fail-level", help="Minimum severity causing non-zero exit code: error, warning, info"
    ),
) -> None:
    """
    Perform a complete scan across an entire directory.
    """
    try:
        cfg = load_config(config_file)
    except Exception as exc:
        console.print(f"[bold red]Failed to load configuration:[/bold red] {exc}")
        raise typer.Exit(code=2)

    target_dir = path.resolve()
    if not target_dir.exists():
        console.print(f"[bold red]Target path does not exist:[/bold red] {target_dir}")
        raise typer.Exit(code=2)

    summary = asyncio.run(execute_scan(cfg, target_dir, diff_result=None))

    if sarif:
        write_sarif_file(summary, sarif)
        console.print(f"[dim]SARIF report exported to {sarif}[/dim]")

    if json_output:
        data = {
            "scanned_files": summary.total_files_scanned,
            "total_violations": summary.total_violations,
            "errors": summary.errors_count,
            "warnings": summary.warnings_count,
            "findings": [
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
        typer.echo(json.dumps(data, indent=2))
    else:
        render_console_report(summary, console=console, fail_on_severity=fail_level)

    if summary.has_failures(fail_level):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command()
def init(
    target: Path = typer.Option(
        Path(".drift-rules.toml"), "--output", "-o", help="Target filename for generated drift rules"
    )
) -> None:
    """
    Generate a default .drift-rules.toml file in the current directory.
    """
    if target.exists():
        console.print(f"[yellow]File already exists:[/yellow] {target}. Will not overwrite.")
        raise typer.Exit(code=1)

    target.write_text(DEFAULT_CONFIG_TOML, encoding="utf-8")
    console.print(f"[bold green]Created default policy file:[/bold green] {target}")


mcp_app = typer.Typer(help="Manage and run the Model Context Protocol (MCP) server.")
app.add_typer(mcp_app, name="mcp")


@mcp_app.command("serve")
def serve_mcp() -> None:
    """Start the GuardRail-Agent MCP server over stdio for Claude Code, Cursor, and Windsurf."""
    from guardrail.server.mcp_server import main
    main()


@app.command()
def version() -> None:
    """Print GuardRail-Agent version."""
    console.print(f"[bold cyan]GuardRail-Agent[/bold cyan] version [bold green]{__version__}[/bold green]")


if __name__ == "__main__":
    app()
