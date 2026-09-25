"""Tests for PDF Report Generation and Email Delivery."""

from pathlib import Path
from guardrail.agent.models import ExecutionPlan, PentestReport
from guardrail.agent.profiler import CodebaseProfile
from guardrail.delivery.email import EmailDelivery
from guardrail.delivery.pdf import ReportGenerator
from guardrail.models import Finding, Severity


def test_report_risk_score_calculation():
    report = PentestReport(
        repo_name="demo-app",
        target_path_or_url="/tmp/demo",
        findings=[
            Finding("OWASP-A03-SQLI", "OwaspScanner", Severity.ERROR, "SQL Injection", "db.py", 10),
            Finding("SEC-002", "SecretsScanner", Severity.ERROR, "AWS Key", "config.py", 5),
        ]
    )
    score = report.calculate_risk_score()
    assert score == "CRITICAL"
    assert report.critical_or_error_count == 2


def test_pdf_report_generation(tmp_path: Path):
    gen = ReportGenerator(output_dir=str(tmp_path))
    profile = CodebaseProfile(target_path=str(tmp_path), languages=["Python"], frameworks=["FastAPI"])
    plan = ExecutionPlan(profile=profile, reasoning_narrative="Target requires OWASP and Secrets scanning.")

    report = PentestReport(
        repo_name="test-project",
        target_path_or_url=str(tmp_path),
        execution_plan=plan,
        findings=[
            Finding("SEC-001", "SecretsScanner", Severity.ERROR, "Committed .env file", ".env", 1),
            Finding("OWASP-A03-CMDI", "OwaspScanner", Severity.ERROR, "Command Injection", "cmd.py", 15, snippet="subprocess.run(cmd, shell=True)"),
        ],
        executive_summary="Target has 2 critical vulnerabilities requiring immediate remediation.",
        remediation_recommendations=["Remove .env file.", "Disable shell=True."],
    )
    report.calculate_risk_score()

    pdf_file = gen.generate_pdf(report)
    assert pdf_file.exists()
    assert pdf_file.stat().st_size > 1000
    assert report.pdf_report_path == str(pdf_file)


def test_email_subject_and_body_construction():
    delivery = EmailDelivery()
    report = PentestReport(
        repo_name="fintech-api",
        target_path_or_url="/app",
        scan_timestamp="2026-09-25 10:00:00 UTC",
        overall_risk_score="CRITICAL",
        executive_summary="Critical payment gateway secrets leaked.",
        findings=[Finding("SEC-002", "SecretsScanner", Severity.ERROR, "Stripe Key leaked", "pay.py", 1)],
    )

    subject = delivery.build_subject(report)
    assert "fintech-api" in subject
    assert "CRITICAL" in subject
    assert "2026-09-25" in subject

    body = delivery.build_body(report)
    assert "fintech-api" in body
    assert "Critical payment gateway secrets leaked." in body
    assert "SEC-002" in body


async def test_email_delivery_simulation_success(tmp_path: Path):
    delivery = EmailDelivery()
    report = PentestReport(
        repo_name="sim-app",
        target_path_or_url=str(tmp_path),
        overall_risk_score="LOW",
        executive_summary="Clean bill of health.",
    )
    success, msg = await delivery.send_report("test@domain.com", report)
    assert success is True
    assert "test@domain.com" in msg


def test_pdf_report_clean_no_findings(tmp_path: Path):
    gen = ReportGenerator(output_dir=str(tmp_path))
    report = PentestReport(
        repo_name="clean-repo",
        target_path_or_url=str(tmp_path),
        findings=[],
        executive_summary="No vulnerabilities detected.",
    )
    report.calculate_risk_score()
    pdf_file = gen.generate_pdf(report)
    assert pdf_file.exists()
    assert report.overall_risk_score == "INFORMATIONAL"
