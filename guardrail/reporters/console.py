"""Rich formatted terminal console reporter for GuardRail-Agent."""

from __future__ import annotations

import sys

# Ensure UTF-8 output streams on Windows
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from guardrail.models import ScanSummary, Severity


def render_console_report(
    summary: ScanSummary,
    console: Console | None = None,
    fail_on_severity: str = "error",
) -> None:
    """Render a comprehensive, color-coded report to the terminal console using Rich."""
    if console is None:
        console = Console(soft_wrap=True)

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan][GuardRail-Agent][/bold cyan] [dim]| AI Codebase Drift & Security Inspection[/dim]",
            border_style="cyan",
        )
    )

    if not summary.findings:
        console.print(
            Panel(
                "[bold green][OK] Clean bill of health![/bold green]\n"
                "No hallucinated dependencies, architectural boundary violations, or security bypasses detected.",
                title="[bold green]PASSED[/bold green]",
                border_style="green",
            )
        )
        return

    # Findings Table
    table = Table(title="Detected AI Codebase Drift & Violations", show_lines=True)
    table.add_column("Severity", justify="center", style="bold", width=12)
    table.add_column("Rule ID", style="bold magenta", width=16)
    table.add_column("Location", style="blue", width=32)
    table.add_column("Description & Remediation", style="white")

    for finding in summary.findings:
        if finding.severity == Severity.ERROR:
            sev_badge = "[bold red]ERROR[/bold red]"
        elif finding.severity == Severity.WARNING:
            sev_badge = "[bold yellow]WARN[/bold yellow]"
        else:
            sev_badge = "[bold cyan]INFO[/bold cyan]"

        loc_str = finding.file_path
        if finding.line_number is not None:
            loc_str += f":{finding.line_number}"
            if finding.column is not None:
                loc_str += f":{finding.column}"

        desc_content = finding.message
        if finding.snippet:
            desc_content += f"\n[dim]Code: {finding.snippet}[/dim]"

        table.add_row(sev_badge, finding.rule_id, loc_str, desc_content)

    console.print(table)
    console.print()

    # Summary Panel
    is_failed = summary.has_failures(fail_on_severity)
    status_color = "red" if is_failed else ("yellow" if summary.warnings_count > 0 else "green")
    status_title = "GATE FAILED" if is_failed else "GATE PASSED"

    summary_text = Text()
    summary_text.append(f"Scanned Files: {summary.total_files_scanned}\n", style="bold")
    summary_text.append(f"Total Violations: {summary.total_violations} ", style="bold")
    summary_text.append(f"([red]{summary.errors_count} errors[/red], [yellow]{summary.warnings_count} warnings[/yellow], [cyan]{summary.info_count} info[/cyan])\n")
    
    if is_failed:
        summary_text.append(
            f"\n[FAIL] Quality gate failed: Found violations matching or exceeding threshold '{fail_on_severity.upper()}'.\n"
            "CI/CD must block this pull request to protect codebase integrity against AI drift.",
            style="bold red",
        )
    else:
        summary_text.append(
            "\n[OK] Quality gate passed (no blocking violations matching failure threshold).",
            style="bold green",
        )

    console.print(Panel(summary_text, title=f"[bold {status_color}]{status_title}[/bold {status_color}]", border_style=status_color))
