"""Unit tests for guardrail.analyzers.architecture using tree-sitter."""

import pytest
from guardrail.config import ArchitectureConfig, ForbiddenImportRule
from guardrail.analyzers.architecture import ArchitectureAnalyzer
from guardrail.git_diff import DiffResult, FileDiff, AddedLine
from guardrail.models import Severity


@pytest.fixture
def sample_config() -> ArchitectureConfig:
    return ArchitectureConfig(
        enabled=True,
        layers={
            "domain": ["**/domain/**", "**/models/**"],
            "application": ["**/application/**", "**/services/**"],
            "infrastructure": ["**/infrastructure/**", "**/database/**"],
            "presentation": ["**/presentation/**", "**/api/**", "**/controllers/**"],
        },
        forbidden_imports=[
            ForbiddenImportRule(
                source_layer="domain",
                disallowed_layers=["infrastructure", "presentation", "application"],
                disallowed_modules=["sqlite3", "requests"],
                reason="Domain must remain pure business logic.",
            ),
            ForbiddenImportRule(
                source_layer="presentation",
                disallowed_layers=["infrastructure"],
                reason="Presentation controllers must not directly touch database/infrastructure.",
            ),
        ],
    )


def test_determine_layer(sample_config):
    analyzer = ArchitectureAnalyzer(sample_config)
    assert analyzer.determine_layer("src/app/domain/user.py") == "domain"
    assert analyzer.determine_layer("backend/models/order.py") == "domain"
    assert analyzer.determine_layer("app/infrastructure/db.py") == "infrastructure"
    assert analyzer.determine_layer("app/api/endpoints.py") == "presentation"
    assert analyzer.determine_layer("random/file.py") is None


def test_parse_imports(sample_config):
    analyzer = ArchitectureAnalyzer(sample_config)
    code = b"""import os, sys
import app.infrastructure.database as db
from app.application.services import UserService
from ..infrastructure import connection
"""
    imports = analyzer.parse_imports(code)
    modules = [imp.module for imp in imports]

    assert "os" in modules
    assert "sys" in modules
    assert "app.infrastructure.database" in modules
    assert "app.application.services" in modules
    assert "infrastructure" in modules or any(imp.is_relative for imp in imports)


def test_domain_importing_infrastructure_violation(sample_config):
    analyzer = ArchitectureAnalyzer(sample_config)
    code = b"""from app.infrastructure.database import SessionLocal
import datetime

class User:
    pass
"""
    findings = analyzer.analyze_file("src/app/domain/user.py", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "GUARD-ARCH-001"
    assert findings[0].severity == Severity.ERROR
    assert "Layer 'domain' is forbidden from importing layer 'infrastructure'" in findings[0].message
    assert findings[0].line_number == 1


def test_domain_importing_disallowed_module(sample_config):
    analyzer = ArchitectureAnalyzer(sample_config)
    code = b"""import sqlite3
import uuid

class Account:
    pass
"""
    findings = analyzer.analyze_file("src/app/domain/account.py", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "GUARD-ARCH-002"
    assert "forbidden from importing module 'sqlite3'" in findings[0].message


def test_diff_filtering_skips_unchanged_lines(sample_config):
    analyzer = ArchitectureAnalyzer(sample_config)
    code = b"""from app.infrastructure.database import SessionLocal
import datetime
"""
    # Simulate a diff where only line 2 (datetime) was added, line 1 is old legacy code
    diff_result = DiffResult(
        files={
            "src/app/domain/user.py": FileDiff(
                path="src/app/domain/user.py",
                status="modified",
                added_lines=[AddedLine(line_number=2, content="import datetime")],
            )
        }
    )

    findings = analyzer.analyze_file("src/app/domain/user.py", code, diff_result=diff_result)
    assert len(findings) == 0

    # If line 1 was added in diff, it must be flagged
    diff_result_added = DiffResult(
        files={
            "src/app/domain/user.py": FileDiff(
                path="src/app/domain/user.py",
                status="modified",
                added_lines=[
                    AddedLine(line_number=1, content="from app.infrastructure.database import SessionLocal")
                ],
            )
        }
    )
    findings2 = analyzer.analyze_file("src/app/domain/user.py", code, diff_result=diff_result_added)
    assert len(findings2) == 1
    assert findings2[0].line_number == 1
