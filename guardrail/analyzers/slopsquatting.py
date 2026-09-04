"""Slopsquatting & Dependency Hallucination Analyzer.

Detects non-existent PyPI packages hallucinated by LLMs (open to slopsquatting registration),
brand-new packages susceptible to malicious takeover, and typosquatting attacks.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import httpx

from guardrail.config import SlopsquattingConfig
from guardrail.git_diff import DependencyChange
from guardrail.models import Finding, Severity

POPULAR_PYTHON_PACKAGES = [
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "pydantic",
    "fastapi",
    "flask",
    "django",
    "pytest",
    "httpx",
    "cryptography",
    "boto3",
    "click",
    "typer",
    "rich",
    "celery",
    "sqlalchemy",
    "scipy",
    "torch",
    "tensorflow",
    "jinja2",
    "werkzeug",
    "aiohttp",
    "paramiko",
    "pillow",
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def check_typosquatting(package_name: str) -> Optional[str]:
    """Return the popular package name if package_name is dangerously similar, else None."""
    clean_name = package_name.lower().replace("_", "-")
    for pop in POPULAR_PYTHON_PACKAGES:
        if clean_name == pop:
            return None  # Exact match to popular package is legitimate
        dist = levenshtein_distance(clean_name, pop)
        # 1 edit distance or 2 edits for longer names
        if (dist == 1 and len(clean_name) >= 4) or (dist == 2 and len(clean_name) >= 8):
            return pop
    return None


def parse_earliest_upload(data: Dict[str, Any]) -> Optional[datetime]:
    """Find the earliest release upload timestamp from PyPI JSON metadata."""
    releases = data.get("releases", {})
    earliest: Optional[datetime] = None

    for version, files in releases.items():
        for f in files:
            upload_str = f.get("upload_time_iso_8601") or f.get("upload_time")
            if upload_str:
                try:
                    if not upload_str.endswith("Z") and "+" not in upload_str:
                        upload_str += "Z"
                    dt = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                    if earliest is None or dt < earliest:
                        earliest = dt
                except Exception:
                    continue
    return earliest


async def analyze_single_package(
    dep: DependencyChange,
    config: SlopsquattingConfig,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> List[Finding]:
    """Check a single dependency against PyPI registry and security heuristics."""
    findings: List[Finding] = []
    pkg = dep.package_name.lower().replace("_", "-")

    # Allowlist check
    normalized_allowlist = {a.lower().replace("_", "-") for a in config.allowlist}
    if pkg in normalized_allowlist:
        return findings

    # Blocklist check
    normalized_blocklist = {b.lower().replace("_", "-") for b in config.blocklist}
    if pkg in normalized_blocklist:
        findings.append(
            Finding(
                rule_id="GUARD-SLOP-000",
                analyzer="slopsquatting",
                severity=Severity.ERROR,
                message=f"Dependency '{dep.package_name}' is explicitly blocklisted by organizational policy.",
                file_path=dep.source_file,
                line_number=dep.line_number,
                snippet=f"{dep.package_name}{dep.specifier}",
                details={"package": dep.package_name, "blocklisted": True},
            )
        )
        return findings

    # Typosquatting heuristic check
    typo_target = check_typosquatting(pkg)
    if typo_target:
        findings.append(
            Finding(
                rule_id="GUARD-SLOP-003",
                analyzer="slopsquatting",
                severity=Severity.WARNING,
                message=(
                    f"Dependency '{dep.package_name}' is suspiciously close to popular package '{typo_target}' "
                    f"(Levenshtein distance <= 2). Verify if this is an intentional package or typosquatting/slopsquatting."
                ),
                file_path=dep.source_file,
                line_number=dep.line_number,
                snippet=f"{dep.package_name}{dep.specifier}",
                details={"package": dep.package_name, "similar_to": typo_target},
            )
        )

    if not config.check_registry:
        return findings

    # Query PyPI registry
    url = config.registry_url.format(package=pkg)
    async with semaphore:
        try:
            response = await client.get(url, timeout=config.timeout_seconds)
            if response.status_code == 404:
                findings.append(
                    Finding(
                        rule_id="GUARD-SLOP-001",
                        analyzer="slopsquatting",
                        severity=Severity.ERROR,
                        message=(
                            f"Hallucinated dependency: '{dep.package_name}' does not exist on PyPI! "
                            f"AI coding agents frequently hallucinate package names. An attacker could register this name "
                            f"on PyPI (Slopsquatting) to execute malicious code on install."
                        ),
                        file_path=dep.source_file,
                        line_number=dep.line_number,
                        snippet=f"{dep.package_name}{dep.specifier}",
                        details={"package": dep.package_name, "status_code": 404},
                    )
                )
                return findings
            elif response.status_code != 200:
                findings.append(
                    Finding(
                        rule_id="GUARD-SLOP-004",
                        analyzer="slopsquatting",
                        severity=Severity.WARNING,
                        message=f"PyPI registry check for '{dep.package_name}' returned HTTP {response.status_code}.",
                        file_path=dep.source_file,
                        line_number=dep.line_number,
                        details={"package": dep.package_name, "status_code": response.status_code},
                    )
                )
                return findings

            # Response is 200 OK - analyze age and metadata
            data = response.json()
            if config.check_age:
                earliest_upload = parse_earliest_upload(data)
                if earliest_upload:
                    age_days = (datetime.now(timezone.utc) - earliest_upload).days
                    if age_days < config.min_package_age_days:
                        severity = Severity.ERROR if age_days < 7 else Severity.WARNING
                        findings.append(
                            Finding(
                                rule_id="GUARD-SLOP-002",
                                analyzer="slopsquatting",
                                severity=severity,
                                message=(
                                    f"Newly registered package: '{dep.package_name}' was first published {age_days} days ago "
                                    f"(minimum policy age is {config.min_package_age_days} days). "
                                    f"Recently registered packages carry elevated supply-chain and slopsquatting risks."
                                ),
                                file_path=dep.source_file,
                                line_number=dep.line_number,
                                snippet=f"{dep.package_name}{dep.specifier}",
                                details={
                                    "package": dep.package_name,
                                    "age_days": age_days,
                                    "first_published": earliest_upload.isoformat(),
                                },
                            )
                        )

        except httpx.RequestError as exc:
            findings.append(
                Finding(
                    rule_id="GUARD-SLOP-005",
                    analyzer="slopsquatting",
                    severity=Severity.INFO,
                    message=f"Unable to query PyPI for '{dep.package_name}': {exc}",
                    file_path=dep.source_file,
                    line_number=dep.line_number,
                    details={"package": dep.package_name, "error": str(exc)},
                )
            )

    return findings


async def check_dependencies_async(
    dependencies: List[DependencyChange],
    config: SlopsquattingConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> List[Finding]:
    """Asynchronously verify all newly introduced dependencies."""
    if not config.enabled or not dependencies:
        return []

    semaphore = asyncio.Semaphore(10)
    findings: List[Finding] = []

    if client is not None:
        tasks = [
            analyze_single_package(dep, config, client, semaphore)
            for dep in dependencies
        ]
        results = await asyncio.gather(*tasks)
        for r in results:
            findings.extend(r)
    else:
        async with httpx.AsyncClient(follow_redirects=True) as new_client:
            tasks = [
                analyze_single_package(dep, config, new_client, semaphore)
                for dep in dependencies
            ]
            results = await asyncio.gather(*tasks)
            for r in results:
                findings.extend(r)

    return findings


def check_dependencies(
    dependencies: List[DependencyChange],
    config: SlopsquattingConfig,
    client: Optional[httpx.AsyncClient] = None,
) -> List[Finding]:
    """Synchronous entry point for dependency checking."""
    return asyncio.run(check_dependencies_async(dependencies, config, client))
