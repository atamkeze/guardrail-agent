"""Agent Reasoning and LLM Decision Engine using Google Gemini / Claude API with offline deterministic fallback."""

from __future__ import annotations

import os
import json
from typing import List, Optional
import httpx

from guardrail.agent.models import CodebaseProfile, ExecutionPlan, PentestReport
from guardrail.models import Finding, Severity


class AgentReasoningEngine:
    """Orchestrates AI reasoning for codebase profiling, execution planning, and findings synthesis."""

    def __init__(self, api_key: Optional[str] = None):
        self.gemini_api_key = (
            api_key
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
        )
        self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")

    async def enhance_execution_plan(self, profile: CodebaseProfile, base_plan: ExecutionPlan) -> ExecutionPlan:
        """Enriches the execution plan using LLM reasoning if API key is provided."""
        if not self.gemini_api_key and not self.anthropic_api_key:
            return base_plan

        prompt = (
            f"You are a Lead Penetration Tester and AI Security Specialist reviewing an application codebase.\n"
            f"Profile:\n"
            f"- Languages: {', '.join(profile.languages)}\n"
            f"- Frameworks: {', '.join(profile.frameworks)}\n"
            f"- Architecture: {profile.architecture_type}\n"
            f"- Database: {profile.database_layer}\n"
            f"- Integrations: {', '.join(profile.external_integrations)}\n"
            f"- Payment Processing: {profile.has_payment_processing}\n"
            f"- Healthcare: {profile.has_healthcare_data}\n"
            f"- Financial: {profile.has_financial_data}\n\n"
            f"Write a concise 3-4 sentence professional justification explaining what attack surfaces exist "
            f"and which security checks (Secrets, OWASP injection, Dependencies, API Security, AI Code checks) must be prioritized."
        )

        ai_narrative = await self._call_llm(prompt)
        if ai_narrative:
            base_plan.reasoning_narrative = ai_narrative.strip()
        return base_plan

    async def synthesize_findings(self, report: PentestReport) -> PentestReport:
        """Synthesizes raw findings into an executive-level security assessment and remediation plan."""
        # Calculate risk score first
        report.calculate_risk_score()

        if self.gemini_api_key or self.anthropic_api_key:
            findings_summary = "\n".join(
                f"- [{f.severity.value.upper()}] {f.rule_id} in {f.file_path}:{f.line_number or 1} - {f.message}"
                for f in report.findings[:30]
            )
            prompt = (
                f"You are a Senior Security Engineer conducting a Penetration Test report review.\n"
                f"Target: {report.repo_name} ({report.target_path_or_url})\n"
                f"Overall Calculated Risk: {report.overall_risk_score}\n"
                f"Findings Breakdown:\n{findings_summary or 'No major critical vulnerabilities found.'}\n\n"
                f"Generate a professional Executive Summary (3-5 sentences) analyzing the systemic impact of these "
                f"findings, followed by 3-5 prioritized remediation recommendations for the engineering leadership team."
            )
            ai_text = await self._call_llm(prompt)
            if ai_text:
                report.executive_summary = ai_text.strip()
                return report

        # Deterministic Senior Security Engineer synthesis fallback (Zero dependency, high reliability)
        criticals = report.critical_or_error_count
        warnings = report.warning_count
        total = report.total_findings

        rules = {f.rule_id for f in report.findings}
        has_sqli = any("SQLI" in r for r in rules)
        has_cmdi = any("CMDI" in r for r in rules)
        has_secrets = any(r.startswith("SEC-") for r in rules)
        has_slop = any("SLOP" in r for r in rules)

        summary_parts = [
            f"GuardRail-Agent completed an autonomous security assessment of {report.repo_name}, identifying {total} "
            f"total finding(s) with an overall risk classification of {report.overall_risk_score}."
        ]

        recs: List[str] = []

        if has_secrets:
            summary_parts.append(
                "High-risk credential leakage was detected, including exposed tokens, API keys, or committed environment files."
            )
            recs.append("Immediately revoke and rotate all compromised API keys and database credentials detected in repository.")
            recs.append("Add automated pre-commit secret detection hooks to prevent future credential commits.")

        if has_sqli or has_cmdi:
            summary_parts.append(
                "Severe injection vulnerabilities (OWASP A03) were flagged where untrusted inputs reach database query execution or OS command execution sinks without parameterization."
            )
            recs.append("Migrate all raw query string concatenations and f-strings to parameterized ORM or prepared statements.")
            recs.append("Refactor system execution calls to remove 'shell=True' and enforce strict argument whitelisting.")

        if has_slop:
            summary_parts.append(
                "Supply chain anomalies were identified, matching hallucinated or unverified third-party dependencies commonly introduced by AI coding tools."
            )
            recs.append("Pin and verify all dependency manifests against official upstream registries (PyPI, npm, Packagist).")

        if not recs:
            summary_parts.append(
                "The target exhibits strong adherence to architectural boundaries with no critical remote code execution or hardcoded credential vectors identified."
            )
            recs.append("Maintain continuous static drift enforcement in CI/CD pipelines on pull requests.")
            recs.append("Periodically audit dependency lockfiles against OSV.dev and national vulnerability databases.")

        report.executive_summary = " ".join(summary_parts)
        report.remediation_recommendations = recs
        return report

    async def _call_llm(self, prompt: str) -> Optional[str]:
        """Calls Gemini API or Claude API via async httpx."""
        # 1. Try Gemini REST API
        if self.gemini_api_key:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.gemini_api_key}"
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1000}
                }
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        candidates = data.get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            if parts:
                                return parts[0].get("text")
            except Exception:
                pass

        # 2. Try Anthropic Messages REST API
        if self.anthropic_api_key:
            try:
                url = "https://api.anthropic.com/v1/messages"
                headers = {
                    "x-api-key": self.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                }
                payload = {
                    "model": "claude-3-5-sonnet-latest",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}]
                }
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(url, headers=headers, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        content = data.get("content", [])
                        if content and content[0].get("type") == "text":
                            return content[0].get("text")
            except Exception:
                pass

        return None
