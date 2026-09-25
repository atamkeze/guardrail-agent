"""Tests for Module E: AI-Generated Code Specific Checks."""

from pathlib import Path
from guardrail.agent.modules.ai_code_checks import AiCodeChecksScanner
from guardrail.models import Severity


def test_ai_vibe_coded_auth_bypass(tmp_path: Path):
    code_file = tmp_path / "auth_service.py"
    # LLM vibe-coding error: calls verify_password as standalone expression without 'if'
    code_file.write_text(
        "def login_handler(username, password):\n"
        "    verify_password(password, stored_hash)\n"  # Forgot if check!
        "    return create_session(username)\n"
    )
    scanner = AiCodeChecksScanner()
    findings = scanner.scan_directory(tmp_path)

    vibe_findings = [f for f in findings if f.rule_id == "AI-VIBE-AUTH-BYPASS"]
    assert len(vibe_findings) == 1
    assert vibe_findings[0].severity == Severity.ERROR
    assert "verify_password" in vibe_findings[0].message


def test_ai_hallucinated_security_function(tmp_path: Path):
    code_file = tmp_path / "crypto_helper.py"
    # LLM hallucination: calling crypto.safe_encrypt or hashlib.sha256_decrypt
    code_file.write_text(
        "def decrypt_data(token):\n"
        "    return hashlib.sha256_decrypt(token)\n"
    )
    scanner = AiCodeChecksScanner()
    findings = scanner.scan_directory(tmp_path)

    hall_findings = [f for f in findings if f.rule_id == "AI-HALLUCINATED-SECURITY-API"]
    assert len(hall_findings) == 1
    assert hall_findings[0].severity == Severity.ERROR


def test_ai_insecure_defaults(tmp_path: Path):
    code_file = tmp_path / "settings.py"
    code_file.write_text(
        "DEBUG = True\n"
        "SECRET_KEY = 'change_me'\n"
    )
    scanner = AiCodeChecksScanner()
    findings = scanner.scan_directory(tmp_path)

    rule_ids = {f.rule_id for f in findings}
    assert "AI-INSECURE-DEFAULT" in rule_ids
    assert len([f for f in findings if f.rule_id == "AI-INSECURE-DEFAULT"]) >= 2


def test_ai_overpermissive_query(tmp_path: Path):
    code_file = tmp_path / "db_queries.py"
    code_file.write_text(
        "def dump_users():\n"
        "    sql = 'SELECT * FROM users'\n"
        "    return db.fetch(sql)\n"
    )
    scanner = AiCodeChecksScanner()
    findings = scanner.scan_directory(tmp_path)

    query_findings = [f for f in findings if f.rule_id == "AI-OVERPERMISSIVE-QUERY"]
    assert len(query_findings) == 1
    assert query_findings[0].severity == Severity.WARNING


def test_ai_safe_code_no_violations(tmp_path: Path):
    code_file = tmp_path / "safe.py"
    code_file.write_text(
        "def safe_auth(password, stored_hash):\n"
        "    if verify_password(password, stored_hash):\n"
        "        return True\n"
        "    return False\n"
    )
    scanner = AiCodeChecksScanner()
    findings = scanner.scan_directory(tmp_path)
    assert len(findings) == 0
