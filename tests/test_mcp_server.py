"""Unit tests for GuardRail-Agent MCP Server tools."""

import json
import pytest
import respx
import httpx
from datetime import datetime, timezone, timedelta

from guardrail.server.mcp_server import (
    verify_dependencies,
    audit_code_drift,
    scan_current_git_diff,
)


@pytest.mark.asyncio
@respx.mock
async def test_mcp_verify_dependencies_hallucinated():
    manifest = """
requests>=2.28.0
hallucinated-ai-fake-auth-sdk==1.0.0
"""
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json={
            "info": {"name": "requests"},
            "releases": {"2.28.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}]}
        })
    )
    respx.get("https://pypi.org/pypi/hallucinated-ai-fake-auth-sdk/json").mock(
        return_value=httpx.Response(404)
    )

    output = await verify_dependencies(manifest, manifest_type="requirements.txt")
    data = json.loads(output)

    assert data["status"] == "failed"
    assert "hallucinated-ai-fake-auth-sdk" in data["hallucinated_packages"]
    assert "requests" in data["verified_packages"]
    assert any("REMOVE hallucinated" in rec for rec in data["recommendations"])


@pytest.mark.asyncio
@respx.mock
async def test_mcp_verify_dependencies_pyproject_toml():
    pyproject_content = """[project]
name = "test-pkg"
dependencies = [
    "pytest>=8.0.0",
    "totally-fake-pypi-library>=0.0.1",
]
"""
    respx.get("https://pypi.org/pypi/pytest/json").mock(
        return_value=httpx.Response(200, json={
            "info": {"name": "pytest"},
            "releases": {"8.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}]}
        })
    )
    respx.get("https://pypi.org/pypi/totally-fake-pypi-library/json").mock(
        return_value=httpx.Response(404)
    )

    output = await verify_dependencies(pyproject_content, manifest_type="pyproject.toml")
    data = json.loads(output)

    assert data["status"] == "failed"
    assert "totally-fake-pypi-library" in data["hallucinated_packages"]
    assert "pytest" in data["verified_packages"]


def test_mcp_audit_code_drift_clean():
    code = """import os
import uuid

class User:
    def __init__(self, name: str):
        self.name = name
"""
    output = audit_code_drift("app/domain/user.py", code)
    data = json.loads(output)

    assert data["status"] == "passed"
    assert data["detected_layer"] == "domain"
    assert data["errors"] == 0
    assert len(data["architectural_violations"]) == 0


def test_mcp_audit_code_drift_violations():
    code = """from app.infrastructure.database import SessionLocal
import httpx

def get_user_data():
    res = httpx.get("https://internal.test", verify=False)  # type: ignore
    return res
"""
    output = audit_code_drift("app/domain/user.py", code)
    data = json.loads(output)

    assert data["status"] == "failed"
    assert data["detected_layer"] == "domain"
    assert data["errors"] >= 2
    assert len(data["architectural_violations"]) >= 1
    assert any(v["rule_id"] == "GUARD-ARCH-001" for v in data["architectural_violations"])
    assert any(s["suppression"] == "# type: ignore" for s in data["linter_suppressions"])
    assert any(d["rule_id"] == "GUARD-SEC-001" for d in data["dangerous_calls"])


@pytest.mark.asyncio
async def test_mcp_scan_current_git_diff_clean():
    output = await scan_current_git_diff()
    data = json.loads(output)

    assert data["verdict"] in ("PASSED", "FAILED")
    assert "total_violations" in data
