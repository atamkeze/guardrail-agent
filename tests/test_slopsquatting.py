"""Unit tests for guardrail.analyzers.slopsquatting using respx."""

import pytest
import respx
import httpx
from datetime import datetime, timezone, timedelta

from guardrail.config import SlopsquattingConfig
from guardrail.git_diff import DependencyChange
from guardrail.models import Severity
from guardrail.analyzers.slopsquatting import (
    check_dependencies_async,
    levenshtein_distance,
    check_typosquatting,
)


def test_levenshtein_distance():
    assert levenshtein_distance("requests", "requests") == 0
    assert levenshtein_distance("requestss", "requests") == 1
    assert levenshtein_distance("fastapi", "fastap") == 1
    assert levenshtein_distance("urllib4", "urllib3") == 1


def test_check_typosquatting():
    assert check_typosquatting("requests") is None  # Legitimate
    assert check_typosquatting("requestss") == "requests"  # Typosquat
    assert check_typosquatting("urllib4") == "urllib3"


@pytest.mark.asyncio
async def test_allowlisted_package_skipped():
    config = SlopsquattingConfig(allowlist=["my-trusted-pkg"])
    dep = DependencyChange(package_name="my-trusted-pkg", specifier=">=1.0", source_file="requirements.txt")

    findings = await check_dependencies_async([dep], config)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_blocklisted_package():
    config = SlopsquattingConfig(blocklist=["malicious-pkg"])
    dep = DependencyChange(package_name="malicious-pkg", specifier=">=1.0", source_file="requirements.txt")

    findings = await check_dependencies_async([dep], config)
    assert len(findings) == 1
    assert findings[0].rule_id == "GUARD-SLOP-000"
    assert findings[0].severity == Severity.ERROR


@pytest.mark.asyncio
@respx.mock
async def test_hallucinated_package_404():
    config = SlopsquattingConfig(allowlist=[], blocklist=[], check_registry=True)
    dep = DependencyChange(
        package_name="ai-hallucinated-auth-helper",
        specifier=">=1.0.0",
        source_file="requirements.txt",
        line_number=10,
    )

    respx.get("https://pypi.org/pypi/ai-hallucinated-auth-helper/json").mock(
        return_value=httpx.Response(404)
    )

    async with httpx.AsyncClient() as client:
        findings = await check_dependencies_async([dep], config, client=client)

    assert len(findings) == 1
    assert findings[0].rule_id == "GUARD-SLOP-001"
    assert findings[0].severity == Severity.ERROR
    assert "does not exist on PyPI" in findings[0].message


@pytest.mark.asyncio
@respx.mock
async def test_newly_registered_package():
    config = SlopsquattingConfig(min_package_age_days=30, check_age=True)
    dep = DependencyChange(
        package_name="brand-new-package",
        specifier="==0.1.0",
        source_file="requirements.txt",
        line_number=5,
    )

    recent_upload = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    mock_pypi_payload = {
        "info": {"name": "brand-new-package", "version": "0.1.0"},
        "releases": {
            "0.1.0": [{"upload_time_iso_8601": recent_upload}]
        },
    }

    respx.get("https://pypi.org/pypi/brand-new-package/json").mock(
        return_value=httpx.Response(200, json=mock_pypi_payload)
    )

    async with httpx.AsyncClient() as client:
        findings = await check_dependencies_async([dep], config, client=client)

    assert len(findings) == 1
    assert findings[0].rule_id == "GUARD-SLOP-002"
    assert "was first published 5 days ago" in findings[0].message


@pytest.mark.asyncio
@respx.mock
async def test_mature_legitimate_package():
    config = SlopsquattingConfig(min_package_age_days=30, check_age=True)
    dep = DependencyChange(
        package_name="mature-lib",
        specifier=">=2.0.0",
        source_file="pyproject.toml",
    )

    old_upload = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    mock_pypi_payload = {
        "info": {"name": "mature-lib", "version": "2.0.0"},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": old_upload}],
            "2.0.0": [{"upload_time_iso_8601": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()}],
        },
    }

    respx.get("https://pypi.org/pypi/mature-lib/json").mock(
        return_value=httpx.Response(200, json=mock_pypi_payload)
    )

    async with httpx.AsyncClient() as client:
        findings = await check_dependencies_async([dep], config, client=client)

    assert len(findings) == 0


@pytest.mark.asyncio
@respx.mock
async def test_typosquatting_and_registry_check():
    config = SlopsquattingConfig()
    dep = DependencyChange(
        package_name="requestss",
        specifier=">=2.0.0",
        source_file="requirements.txt",
    )

    respx.get("https://pypi.org/pypi/requestss/json").mock(
        return_value=httpx.Response(404)
    )

    async with httpx.AsyncClient() as client:
        findings = await check_dependencies_async([dep], config, client=client)

    rule_ids = {f.rule_id for f in findings}
    assert "GUARD-SLOP-003" in rule_ids  # Typosquat heuristic
    assert "GUARD-SLOP-001" in rule_ids  # 404 hallucination
