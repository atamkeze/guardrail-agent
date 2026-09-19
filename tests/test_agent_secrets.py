"""Tests for the Autonomous Pentest Agent Secrets Scanner."""

from pathlib import Path
from guardrail.agent.modules.secrets import SecretsScanner, shannon_entropy
from guardrail.models import Severity

def test_shannon_entropy():
    # Low entropy (repeated characters)
    low_ent = shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert low_ent == 0.0

    # High entropy (random base64)
    high_ent = shannon_entropy("aB3k9XyZ1pQr7vNw4mJt6cL")
    assert high_ent > 4.0

def test_secrets_scanner_regex(tmp_path: Path):
    # Create a dummy file with a leaked AWS key
    code_file = tmp_path / "config.py"
    code_file.write_text("aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'\n")
    
    scanner = SecretsScanner()
    findings = scanner.scan_directory(tmp_path)
    
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-002"
    assert "AWS Access Key" in findings[0].message
    assert findings[0].severity == Severity.ERROR

def test_secrets_scanner_env_file(tmp_path: Path):
    env_file = tmp_path / ".env.production"
    env_file.write_text("DB_PASS=supersecret")
    
    scanner = SecretsScanner()
    findings = scanner.scan_directory(tmp_path)
    
    # One finding for the .env file itself
    env_findings = [f for f in findings if f.rule_id == "SEC-001"]
    assert len(env_findings) == 1
    assert env_findings[0].severity == Severity.ERROR
    assert env_findings[0].file_path == ".env.production"

def test_secrets_scanner_entropy(tmp_path: Path):
    # A long random string that doesn't match standard regex but has high entropy
    # E.g., a random custom API key
    random_str = "x8A9kLmN2pQrY6zV0wB4jT1fC5dE7gH3"
    
    code_file = tmp_path / "auth.py"
    code_file.write_text(f"CUSTOM_TOKEN = '{random_str}'\n")
    
    scanner = SecretsScanner()
    findings = scanner.scan_directory(tmp_path)
    
    ent_findings = [f for f in findings if f.rule_id == "SEC-003"]
    assert len(ent_findings) == 1
    assert "High entropy string detected" in ent_findings[0].message
    assert ent_findings[0].severity == Severity.WARNING

def test_secrets_scanner_ignore_example_env(tmp_path: Path):
    env_file = tmp_path / ".env.example"
    env_file.write_text("DB_PASS=placeholder")
    
    scanner = SecretsScanner()
    findings = scanner.scan_directory(tmp_path)
    
    # Should not flag .env.example as a committed secret file
    env_findings = [f for f in findings if f.rule_id == "SEC-001"]
    assert len(env_findings) == 0
