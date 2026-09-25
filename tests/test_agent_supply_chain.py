"""Tests for Module A: Supply Chain & Dependency Scanner with OSV.dev and PyPI."""

import json
from pathlib import Path
import pytest
import respx
import httpx
from guardrail.agent.modules.supply_chain import SupplyChainScanner


@pytest.mark.asyncio
async def test_supply_chain_parses_requirements_txt(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\nurllib3>=1.26.5\n")

    scanner = SupplyChainScanner()
    with respx.mock(base_url="https://api.osv.dev") as respx_mock:
        respx_mock.post("/v1/query").respond(200, json={"vulns": []})
        findings = await scanner.scan_dependencies(tmp_path)
        # Should complete without error
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_supply_chain_parses_package_json(tmp_path: Path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "sample-node-app",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "4.17.20"
        }
    }))

    scanner = SupplyChainScanner()
    with respx.mock(base_url="https://api.osv.dev") as respx_mock:
        respx_mock.post("/v1/query").respond(200, json={"vulns": []})
        findings = await scanner.scan_dependencies(tmp_path)
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_supply_chain_parses_composer_json(tmp_path: Path):
    composer = tmp_path / "composer.json"
    composer.write_text(json.dumps({
        "name": "sample/php-app",
        "require": {
            "guzzlehttp/guzzle": "^7.0"
        }
    }))

    scanner = SupplyChainScanner()
    with respx.mock(base_url="https://api.osv.dev") as respx_mock:
        respx_mock.post("/v1/query").respond(200, json={"vulns": []})
        findings = await scanner.scan_dependencies(tmp_path)
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_supply_chain_osv_vulnerability_flagged(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("vulnerable-pkg==1.0.0\n")

    scanner = SupplyChainScanner()
    fake_vuln = {
        "vulns": [
            {
                "id": "GHSA-1234-5678-9999",
                "summary": "Remote Code Execution via deserialization in vulnerable-pkg",
                "aliases": ["CVE-2026-99999"]
            }
        ]
    }

    with respx.mock(base_url="https://api.osv.dev") as respx_mock:
        respx_mock.post("/v1/query").respond(200, json=fake_vuln)
        findings = await scanner.scan_dependencies(tmp_path)

        cve_findings = [f for f in findings if "CVE-GHSA-1234-5678-9999" in f.rule_id]
        assert len(cve_findings) == 1
        assert "Remote Code Execution" in cve_findings[0].message
        assert cve_findings[0].file_path == "requirements.txt"


@pytest.mark.asyncio
async def test_supply_chain_clean_project(tmp_path: Path):
    # No dependency files present
    scanner = SupplyChainScanner()
    findings = await scanner.scan_dependencies(tmp_path)
    assert len(findings) == 0
