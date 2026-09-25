"""Email Delivery service for GuardRail-Agent reports supporting Resend, SendGrid, and SMTP."""

from __future__ import annotations

import base64
import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional, Tuple
import httpx

from guardrail.agent.models import PentestReport
from guardrail.models import Severity


class EmailDelivery:
    """Dispatches executive security reports and PDF attachments via Resend, SendGrid, or SMTP."""

    def __init__(self):
        self.resend_api_key = os.environ.get("RESEND_API_KEY")
        self.sendgrid_api_key = os.environ.get("SENDGRID_API_KEY")
        self.smtp_host = os.environ.get("SMTP_HOST")
        self.smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        self.smtp_user = os.environ.get("SMTP_USER")
        self.smtp_password = os.environ.get("SMTP_PASSWORD")
        self.sender_email = os.environ.get("GUARDRAIL_SENDER_EMAIL", "security@guardrail-agent.dev")

    def build_subject(self, report: PentestReport) -> str:
        date_str = report.scan_timestamp.split(" ")[0]
        return f"GuardRail-Agent Security Report - {report.repo_name} - [{report.overall_risk_score}] - {date_str}"

    def build_body(self, report: PentestReport) -> str:
        top_findings = [
            f"- [{f.severity.value.upper()}] {f.rule_id} in {f.file_path}:{f.line_number or 1} -> {f.message}"
            for f in report.findings if f.severity in (Severity.ERROR, Severity.WARNING)
        ][:5]

        findings_text = "\n".join(top_findings) if top_findings else "- No critical or high severity findings detected."

        body = (
            f"GuardRail-Agent Automated Security Assessment\n"
            f"=============================================\n"
            f"Target: {report.repo_name}\n"
            f"Risk Rating: {report.overall_risk_score}\n"
            f"Date: {report.scan_timestamp}\n\n"
            f"EXECUTIVE SUMMARY:\n"
            f"{report.executive_summary}\n\n"
            f"TOP CRITICAL / HIGH FINDINGS:\n"
            f"{findings_text}\n\n"
            f"Attached is the full comprehensive PDF audit report.\n"
            f"---\n"
            f"Delivered automatically by GuardRail-Agent Autonomous Pentest Gate\n"
        )
        return body

    async def send_report(self, recipient: str, report: PentestReport, pdf_path: Optional[Path] = None) -> Tuple[bool, str]:
        subject = self.build_subject(report)
        body = self.build_body(report)
        target_pdf = pdf_path or (Path(report.pdf_report_path) if report.pdf_report_path else None)

        # 1. Try Resend API
        if self.resend_api_key:
            try:
                attachments = []
                if target_pdf and target_pdf.is_file():
                    content_b64 = base64.b64encode(target_pdf.read_bytes()).decode("utf-8")
                    attachments.append({
                        "filename": target_pdf.name,
                        "content": content_b64,
                    })

                url = "https://api.resend.com/emails"
                headers = {
                    "Authorization": f"Bearer {self.resend_api_key}",
                    "Content-Type": "application/json",
                }
                payload = {
                    "from": self.sender_email,
                    "to": [recipient],
                    "subject": subject,
                    "text": body,
                    "attachments": attachments,
                }
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        return True, f"Email sent via Resend API to {recipient}"
                    return False, f"Resend error: {resp.text}"
            except Exception as e:
                return False, f"Resend exception: {str(e)}"

        # 2. Try SendGrid API
        if self.sendgrid_api_key:
            try:
                url = "https://api.sendgrid.com/v3/mail/send"
                headers = {
                    "Authorization": f"Bearer {self.sendgrid_api_key}",
                    "Content-Type": "application/json",
                }
                attachments = []
                if target_pdf and target_pdf.is_file():
                    content_b64 = base64.b64encode(target_pdf.read_bytes()).decode("utf-8")
                    attachments.append({
                        "content": content_b64,
                        "filename": target_pdf.name,
                        "type": "application/pdf",
                        "disposition": "attachment",
                    })

                payload = {
                    "personalizations": [{"to": [{"email": recipient}]}],
                    "from": {"email": self.sender_email},
                    "subject": subject,
                    "content": [{"type": "text/plain", "value": body}],
                    "attachments": attachments,
                }
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code in (200, 202):
                        return True, f"Email sent via SendGrid to {recipient}"
                    return False, f"SendGrid error: {resp.text}"
            except Exception as e:
                return False, f"SendGrid exception: {str(e)}"

        # 3. Try standard SMTP
        if self.smtp_host and self.smtp_user and self.smtp_password:
            try:
                msg = MIMEMultipart()
                msg["From"] = self.sender_email
                msg["To"] = recipient
                msg["Subject"] = subject
                msg.attach(MIMEText(body, "plain"))

                if target_pdf and target_pdf.is_file():
                    with open(target_pdf, "rb") as f:
                        part = MIMEApplication(f.read(), Name=target_pdf.name)
                        part["Content-Disposition"] = f'attachment; filename="{target_pdf.name}"'
                        msg.attach(part)

                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                    server.send_message(msg)

                return True, f"Email sent via SMTP to {recipient}"
            except Exception as e:
                return False, f"SMTP error: {str(e)}"

        # 4. Fallback simulation (No provider credentials configured)
        return True, f"Simulated email delivery to {recipient} (configure RESEND_API_KEY, SENDGRID_API_KEY, or SMTP_HOST to send live emails)"
