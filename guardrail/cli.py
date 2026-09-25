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


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]GuardRail-Agent[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show the application version and exit.", callback=version_callback, is_eager=True
    ),
) -> None:
    """GuardRail-Agent: AI Codebase Drift & Security Inspection Gate."""
    pass


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


mcp_app = typer.Typer(
    help="Manage and run the Model Context Protocol (MCP) server.",
    invoke_without_command=True,
)
app.add_typer(mcp_app, name="mcp")


@mcp_app.callback(invoke_without_command=True)
def mcp_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        from guardrail.server.mcp_server import main
        main()


@mcp_app.command("serve")
def serve_mcp() -> None:
    """Start the GuardRail-Agent MCP server over stdio for Claude Code, Cursor, and Windsurf."""
    from guardrail.server.mcp_server import main
    main()


@app.command()
def pentest(
    target: str = typer.Argument(".", help="Path to codebase directory or remote GitHub repository URL"),
    email: Optional[str] = typer.Option(None, "--email", "-e", help="Recipient email address for automated PDF report delivery"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-o", help="Custom directory for generated PDF reports"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Optional Gemini or Claude API key for AI reasoning"),
) -> None:
    """
    Launch Autonomous Penetration Testing Agent with dynamic risk reasoning and PDF/Email delivery.
    """
    from guardrail.agent.pentest import AutonomousPentestAgent

    console.print("\n[bold cyan]╔════════════════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║[/bold cyan]  [bold white]GuardRail-Agent[/bold white] [dim]|[/dim] [bold red]Autonomous Penetration Testing Gate v2.0[/bold red]      [bold cyan]║[/bold cyan]")
    console.print("[bold cyan]╚════════════════════════════════════════════════════════════════╝[/bold cyan]\n")

    agent = AutonomousPentestAgent(api_key=api_key)
    if output_dir:
        agent.pdf_generator.output_dir = Path(output_dir)

    def cli_progress(stage: str, msg: str):
        if stage in ("profiling", "planning", "scanning", "synthesis", "report", "delivery"):
            console.print(f"[bold yellow]▶[/bold yellow] [dim]{msg}[/dim]")
        elif stage == "reasoning_complete":
            console.print(f"\n[bold magenta]┌─ Agent Threat Model & Reasoning ─────────────────────────────┐[/bold magenta]")
            console.print(f"[italic white]{msg}[/italic white]")
            console.print(f"[bold magenta]└──────────────────────────────────────────────────────────────┘[/bold magenta]\n")

    try:
        report = asyncio.run(agent.run_pentest(target, email_recipient=email, progress_callback=cli_progress))

        # Risk Banner
        score = report.overall_risk_score
        score_color = "bold red" if score in ("CRITICAL", "HIGH") else "bold yellow" if score == "MEDIUM" else "bold green"
        console.print(f"\n[bold white]Audit Result:[/bold white] [{score_color}]{score} RISK[/{score_color}] [dim]({report.total_findings} total findings in {report.duration_seconds}s)[/dim]")

        # Executive Summary
        console.print(f"\n[bold cyan]Executive Summary:[/bold cyan]\n{report.executive_summary}\n")

        # Top Findings Table
        if report.findings:
            from rich.table import Table
            table = Table(title="Detected Vulnerabilities & Drift Violations", show_header=True, header_style="bold magenta")
            table.add_column("Severity", width=10)
            table.add_column("Rule ID", width=18)
            table.add_column("Location", width=25)
            table.add_column("Description", min_width=35)

            for f in report.findings[:20]:
                sev_style = "bold red" if f.severity.value == "error" else "yellow" if f.severity.value == "warning" else "cyan"
                table.add_row(
                    f"[{sev_style}]{f.severity.value.upper()}[/{sev_style}]",
                    f.rule_id,
                    f"{f.file_path}:{f.line_number or 1}",
                    f.message,
                )
            console.print(table)
            if len(report.findings) > 20:
                console.print(f"[dim]... and {len(report.findings) - 20} additional finding(s) documented in PDF report.[/dim]")

        if report.pdf_report_path:
            console.print(f"\n[bold green]✔ PDF Report generated:[/bold green] [bold underline]{report.pdf_report_path}[/bold underline]")

        if email:
            console.print(f"[bold green]✔ Report dispatched to:[/bold green] {email}")

    except Exception as exc:
        console.print(f"\n[bold red]Pentest Agent encountered an error:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host for local web dashboard"),
    port: int = typer.Option(8000, "--port", "-p", help="Port for local web dashboard"),
) -> None:
    """
    Launch the GuardRail-Agent interactive real-time web dashboard.
    """
    import uvicorn

    console.print(f"\n[bold cyan]GuardRail-Agent[/bold cyan] Web Dashboard starting at: [bold green]http://{host}:{port}[/bold green]")
    console.print("[dim]Press Ctrl+C to terminate the dashboard server.[/dim]\n")
    uvicorn.run("guardrail.web.app:app", host=host, port=port, reload=False)


@app.command()
def version() -> None:
    """Print GuardRail-Agent version."""
    console.print(f"[bold cyan]GuardRail-Agent[/bold cyan] version [bold green]{__version__}[/bold green]")


if __name__ == "__main__":
    app()

