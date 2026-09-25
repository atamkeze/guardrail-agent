"""Codebase Profiler for Autonomous Pentest Agent."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from guardrail.agent.models import CodebaseProfile, ExecutionPlan, ModuleSelection
from guardrail.cli import collect_project_files

LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript (React)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (React)",
    ".php": "PHP",
    ".dart": "Dart",
    ".go": "Go",
    ".java": "Java",
    ".kt": "Kotlin",
    ".rb": "Ruby",
    ".cs": "C#",
    ".rs": "Rust",
    ".html": "HTML",
    ".sql": "SQL",
}

PAYMENT_KEYWORDS = {
    "stripe", "paypal", "notchpay", "paystack", "flutterwave", "braintree",
    "payment", "checkout", "creditcard", "billing", "invoice", "stripe_secret",
}

HEALTHCARE_KEYWORDS = {
    "hipaa", "patient", "ehr", "fhir", "medical", "health_record", "clinical",
    "doctor", "prescription",
}

FINANCIAL_KEYWORDS = {
    "bank", "account_number", "routing_number", "iban", "swift", "balance",
    "ledger", "wallet", "crypto", "currency", "transaction",
}


class CodebaseProfiler:
    """Analyzes a codebase statically to extract architectural profile, technology stack, and attack surfaces."""

    def __init__(self, exclude_patterns: List[str] = None):
        self.exclude_patterns = exclude_patterns or [
            ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", "dist", "build"
        ]

    def profile_directory(self, root: Path) -> CodebaseProfile:
        root_path = root.resolve()
        profile = CodebaseProfile(target_path=str(root_path))
        files = collect_project_files(root_path, self.exclude_patterns)

        detected_languages: Set[str] = set()
        detected_frameworks: Set[str] = set()
        entry_points: List[str] = []
        external_integrations: Set[str] = set()

        db_indicators: Set[str] = set()
        auth_indicators: Set[str] = set()

        has_payment = False
        has_health = False
        has_financial = False

        # 1. Manifest and configuration inspection
        for f in files:
            fname = f.name.lower()
            rel_str = str(f.relative_to(root_path)).replace("\\", "/")

            # Entry points
            if fname in ("app.py", "main.py", "server.js", "index.js", "index.ts", "index.php", "artisan", "manage.py"):
                entry_points.append(rel_str)

            # File extensions
            ext = f.suffix.lower()
            if ext in LANGUAGE_EXTENSIONS:
                detected_languages.add(LANGUAGE_EXTENSIONS[ext])

            # Check manifests
            if fname == "composer.json":
                detected_frameworks.add("PHP/Composer")
                try:
                    c_text = f.read_text(encoding="utf-8", errors="ignore").lower()
                    if "laravel/framework" in c_text:
                        detected_frameworks.add("Laravel")
                    if "symfony" in c_text:
                        detected_frameworks.add("Symfony")
                    if "notchpay" in c_text:
                        external_integrations.add("NotchPay")
                        has_payment = True
                    if "stripe" in c_text:
                        external_integrations.add("Stripe")
                        has_payment = True
                except Exception:
                    pass

            elif fname in ("pyproject.toml", "requirements.txt"):
                try:
                    req_text = f.read_text(encoding="utf-8", errors="ignore").lower()
                    if "fastapi" in req_text:
                        detected_frameworks.add("FastAPI")
                    if "flask" in req_text:
                        detected_frameworks.add("Flask")
                    if "django" in req_text:
                        detected_frameworks.add("Django")
                    if "sqlalchemy" in req_text:
                        db_indicators.add("SQLAlchemy")
                    if "pymongo" in req_text or "motor" in req_text:
                        db_indicators.add("MongoDB")
                    if "psycopg" in req_text or "asyncpg" in req_text:
                        db_indicators.add("PostgreSQL")
                    if "mysql" in req_text:
                        db_indicators.add("MySQL")
                    if "jwt" in req_text or "pyjwt" in req_text:
                        auth_indicators.add("JWT Authentication")
                    if "stripe" in req_text:
                        external_integrations.add("Stripe")
                        has_payment = True
                    if "notchpay" in req_text:
                        external_integrations.add("NotchPay")
                        has_payment = True
                except Exception:
                    pass

            elif fname == "package.json":
                try:
                    pkg_text = f.read_text(encoding="utf-8", errors="ignore").lower()
                    if "express" in pkg_text:
                        detected_frameworks.add("Express.js")
                    if "react" in pkg_text:
                        detected_frameworks.add("React")
                    if "next" in pkg_text:
                        detected_frameworks.add("Next.js")
                    if "prisma" in pkg_text:
                        db_indicators.add("Prisma ORM")
                    if "mongoose" in pkg_text:
                        db_indicators.add("Mongoose (MongoDB)")
                    if "jsonwebtoken" in pkg_text or "passport" in pkg_text:
                        auth_indicators.add("JWT/Passport Auth")
                    if "stripe" in pkg_text:
                        external_integrations.add("Stripe")
                        has_payment = True
                except Exception:
                    pass

            # Shallow keyword scan on code lines
            if ext in (".py", ".js", ".ts", ".php", ".env", ".toml", ".json"):
                try:
                    content_lower = f.read_text(encoding="utf-8", errors="ignore")[:5000].lower()
                    for kw in PAYMENT_KEYWORDS:
                        if kw in content_lower:
                            has_payment = True
                            if kw in ("stripe", "paypal", "notchpay", "paystack", "flutterwave"):
                                external_integrations.add(kw.capitalize())
                    for kw in HEALTHCARE_KEYWORDS:
                        if kw in content_lower:
                            has_health = True
                    for kw in FINANCIAL_KEYWORDS:
                        if kw in content_lower:
                            has_financial = True
                except Exception:
                    pass

        # Summarize architecture type
        if "Laravel" in detected_frameworks or "FastAPI" in detected_frameworks or "Express.js" in detected_frameworks:
            arch_type = "REST API / Web Service"
        elif "Django" in detected_frameworks or "Next.js" in detected_frameworks:
            arch_type = "Fullstack Web Application"
        elif any(f.name.endswith(".dart") for f in files) or "Dart" in detected_languages:
            arch_type = "Mobile Application / Backend"
        elif "Python" in detected_languages and not detected_frameworks:
            arch_type = "Python Application / CLI Tool"
        else:
            arch_type = "Software Application"

        profile.languages = sorted(list(detected_languages))
        profile.frameworks = sorted(list(detected_frameworks))
        profile.architecture_type = arch_type
        profile.entry_points = entry_points[:5]
        profile.database_layer = ", ".join(sorted(list(db_indicators))) if db_indicators else "Standard Database / ORM"
        profile.auth_mechanism = ", ".join(sorted(list(auth_indicators))) if auth_indicators else "Token/Session Auth"
        profile.external_integrations = sorted(list(external_integrations))
        profile.has_payment_processing = has_payment
        profile.has_healthcare_data = has_health
        profile.has_financial_data = has_financial

        framework_str = "/".join(profile.frameworks) if profile.frameworks else "Native Code"
        profile.summary = (
            f"{framework_str} ({profile.architecture_type}) utilizing "
            f"{', '.join(profile.languages) or 'various languages'}"
        )
        return profile

    def create_execution_plan(self, profile: CodebaseProfile) -> ExecutionPlan:
        """Dynamically decides which security modules to run based on risk weights."""
        selections: List[ModuleSelection] = []

        # Module A: Dependency & Supply Chain
        dep_priority = "MAXIMUM" if profile.has_payment_processing or profile.has_financial_data else "HIGH"
        dep_weight = 0.95 if dep_priority == "MAXIMUM" else 0.80
        selections.append(ModuleSelection(
            module_id="module_a",
            name="Dependency & Supply Chain Scanner (Slopsquatting & OSV.dev CVEs)",
            priority=dep_priority,
            weight=dep_weight,
            reason="High risk of supply-chain attacks and hallucinated package injection.",
            enabled=True,
        ))

        # Module B: Secrets & Credentials
        sec_priority = "MAXIMUM" if (profile.has_payment_processing or profile.external_integrations) else "HIGH"
        sec_weight = 1.0 if sec_priority == "MAXIMUM" else 0.85
        selections.append(ModuleSelection(
            module_id="module_b",
            name="Secrets & Credential Leakage Scanner (Entropy & Token Analysis)",
            priority=sec_priority,
            weight=sec_weight,
            reason="Guards against hardcoded API tokens, private keys, and payment credentials.",
            enabled=True,
        ))

        # Module C: OWASP Top 10 Static Analysis
        owasp_priority = "MAXIMUM" if ("API" in profile.architecture_type or "Web" in profile.architecture_type) else "HIGH"
        owasp_weight = 0.95 if owasp_priority == "MAXIMUM" else 0.75
        selections.append(ModuleSelection(
            module_id="module_c",
            name="OWASP Top 10 Static Analysis (SQLi, CMDi, Deserialization via AST)",
            priority=owasp_priority,
            weight=owasp_weight,
            reason="Target has network entry points exposed to untrusted external input.",
            enabled=True,
        ))

        # Module D: Architecture & API Security
        is_api = any(f in ("Laravel", "FastAPI", "Flask", "Django", "Express.js") for f in profile.frameworks) or "API" in profile.architecture_type
        api_priority = "MAXIMUM" if is_api else "MEDIUM"
        api_weight = 0.90 if is_api else 0.60
        selections.append(ModuleSelection(
            module_id="module_d",
            name="Architecture & API Security Analysis (Unauthenticated Routes, IDOR, Mass Assignment)",
            priority=api_priority,
            weight=api_weight,
            reason="Enforces API access controls, authentication middleware, and Clean Architecture.",
            enabled=True,
        ))

        # Module E: AI-Generated Code Specific Checks
        selections.append(ModuleSelection(
            module_id="module_e",
            name="AI-Generated Code Specific Checks (Vibe-Coded Bypasses, Hallucinated Security APIs)",
            priority="HIGH",
            weight=0.85,
            reason="Detects subtle insecure defaults and hallucinated safety checks injected by LLM assistants.",
            enabled=True,
        ))

        # Generate Senior Security Engineer reasoning string
        integrations_desc = f" with {', '.join(profile.external_integrations)} integration" if profile.external_integrations else ""
        db_desc = f" and {profile.database_layer}" if profile.database_layer else ""
        
        prioritized_names = [s.name.split(" (")[0] for s in sorted(selections, key=lambda x: x.weight, reverse=True)]
        
        narrative = (
            f"I have detected a {profile.architecture_type} ({', '.join(profile.frameworks) or 'Polyglot'})"
            f"{integrations_desc}{db_desc}. "
            f"Based on this threat model, I will prioritize: "
            f"{', '.join(prioritized_names[:3])}, followed by {', '.join(prioritized_names[3:])}. "
            f"Core AST drift rules and boundary enforcement remain active."
        )

        return ExecutionPlan(
            profile=profile,
            selected_modules=selections,
            reasoning_narrative=narrative,
        )
