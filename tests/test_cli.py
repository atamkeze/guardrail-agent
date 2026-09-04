"""Unit tests for guardrail.cli using Typer CliRunner."""

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner

from guardrail.cli import app
from guardrail import __version__

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_cli_init(tmp_path: Path):
    target_toml = tmp_path / ".drift-rules.toml"
    result = runner.invoke(app, ["init", "--output", str(target_toml)])
    assert result.exit_code == 0
    assert target_toml.exists()
    content = target_toml.read_text(encoding="utf-8")
    assert "[general]" in content
    assert "[slopsquatting]" in content
    assert "[architecture]" in content


def test_cli_scan_clean_dir(tmp_path: Path):
    # Clean Python file with no violations
    code_file = tmp_path / "clean.py"
    code_file.write_text("import os\nprint('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "PASSED" in result.stdout


def test_cli_scan_violation_exits_nonzero(tmp_path: Path):
    # Create architecture violation: domain importing infrastructure
    domain_dir = tmp_path / "domain"
    domain_dir.mkdir(parents=True)
    bad_file = domain_dir / "user.py"
    bad_file.write_text("from app.infrastructure.database import db\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "GUARD-ARCH-001" in result.stdout or "GATE FAILED" in result.stdout


def test_cli_scan_sarif_export(tmp_path: Path):
    bad_file = tmp_path / "insecure.py"
    bad_file.write_text("eval('secret')\n", encoding="utf-8")
    sarif_file = tmp_path / "report.sarif"

    result = runner.invoke(app, ["scan", str(tmp_path), "--sarif", str(sarif_file)])
    assert result.exit_code == 1
    assert sarif_file.exists()

    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) >= 1


def test_cli_scan_json_output(tmp_path: Path):
    bad_file = tmp_path / "bypass.py"
    bad_file.write_text("val = 1 # noqa\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["total_violations"] >= 1
    assert data["findings"][0]["rule_id"] == "GUARD-BYPASS-001"
