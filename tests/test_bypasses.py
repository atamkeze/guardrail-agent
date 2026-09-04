"""Unit tests for guardrail.analyzers.bypasses."""

import pytest
from guardrail.config import BypassesConfig, DangerousCallRule
from guardrail.analyzers.bypasses import BypassesAnalyzer
from guardrail.git_diff import DiffResult, FileDiff, AddedLine
from guardrail.models import Severity


@pytest.fixture
def default_config() -> BypassesConfig:
    return BypassesConfig(
        enabled=True,
        max_new_suppressions=0,
        forbidden_suppressions=["# noqa", "# type: ignore", "// @ts-ignore", "# nosec"],
        dangerous_calls=[
            DangerousCallRule(pattern=r"verify\s*=\s*False", severity="error", message="Disabled TLS"),
            DangerousCallRule(pattern=r"shell\s*=\s*True", severity="error", message="subprocess shell=True"),
            DangerousCallRule(pattern=r"\beval\s*\(", severity="error", message="eval() detected"),
        ],
        exempt_paths=["tests/**", "*_test.py", "test_*.py"],
    )


def test_detect_linter_suppression(default_config):
    analyzer = BypassesAnalyzer(default_config)
    code = """x = 1  # noqa
y = "test"  # type: ignore
z = 3
"""
    findings = analyzer.analyze_file("src/app/utils.py", code)
    assert len(findings) == 2
    assert all(f.rule_id == "GUARD-BYPASS-001" for f in findings)
    assert findings[0].line_number == 1
    assert findings[1].line_number == 2


def test_detect_dangerous_calls(default_config):
    analyzer = BypassesAnalyzer(default_config)
    code = """import httpx, subprocess

res = httpx.get("https://insecure.internal", verify=False)
subprocess.run("rm -rf " + path, shell=True)
res = eval("2 + 2")
"""
    findings = analyzer.analyze_file("src/app/client.py", code)
    assert len(findings) == 3
    rule_ids = [f.rule_id for f in findings]
    assert "GUARD-SEC-001" in rule_ids  # verify=False
    assert "GUARD-SEC-002" in rule_ids  # shell=True
    assert "GUARD-SEC-003" in rule_ids  # eval


def test_exempt_paths_are_skipped(default_config):
    analyzer = BypassesAnalyzer(default_config)
    code = """# noqa
eval("test")
"""
    # Test file should be skipped
    findings = analyzer.analyze_file("tests/test_something.py", code)
    assert len(findings) == 0

    findings2 = analyzer.analyze_file("src/app/something_test.py", code)
    assert len(findings2) == 0


def test_diff_mode_only_flags_added_lines(default_config):
    analyzer = BypassesAnalyzer(default_config)
    code = """line1 = 1  # noqa (old legacy code)
line2 = eval("new_code")
"""
    # Only line 2 is in the diff
    diff_result = DiffResult(
        files={
            "src/app/main.py": FileDiff(
                path="src/app/main.py",
                status="modified",
                added_lines=[AddedLine(line_number=2, content='line2 = eval("new_code")')],
            )
        }
    )

    findings = analyzer.analyze_file("src/app/main.py", code, diff_result=diff_result)
    assert len(findings) == 1
    assert findings[0].line_number == 2
    assert findings[0].rule_id == "GUARD-SEC-003"
