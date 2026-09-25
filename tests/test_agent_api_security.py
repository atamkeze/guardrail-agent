"""Tests for Module D: Architecture and API Security Analysis."""

from pathlib import Path
from guardrail.agent.modules.api_security import ApiSecurityScanner
from guardrail.models import Severity


def test_api_security_unauthenticated_sensitive_route(tmp_path: Path):
    api_file = tmp_path / "routes.py"
    api_file.write_text(
        "@app.delete('/api/admin/users/{user_id}')\n"
        "def delete_user(user_id: int):\n"
        "    return {'status': 'deleted'}\n"
    )
    scanner = ApiSecurityScanner()
    findings = scanner.scan_directory(tmp_path)

    auth_findings = [f for f in findings if f.rule_id == "API-AUTH-MISSING"]
    assert len(auth_findings) == 1
    assert auth_findings[0].severity == Severity.ERROR
    assert "delete_user" in auth_findings[0].message


def test_api_security_authenticated_route_passed(tmp_path: Path):
    api_file = tmp_path / "safe_routes.py"
    api_file.write_text(
        "@app.delete('/api/admin/users/{user_id}')\n"
        "def delete_user(user_id: int, current_user = Depends(get_current_admin)):\n"
        "    return {'status': 'deleted'}\n"
    )
    scanner = ApiSecurityScanner()
    findings = scanner.scan_directory(tmp_path)

    auth_findings = [f for f in findings if f.rule_id == "API-AUTH-MISSING"]
    assert len(auth_findings) == 0


def test_api_security_missing_rate_limit(tmp_path: Path):
    api_file = tmp_path / "auth_routes.py"
    api_file.write_text(
        "@app.post('/api/auth/login')\n"
        "def login_user(creds: LoginSchema):\n"
        "    return {'token': 'jwt_token'}\n"
    )
    scanner = ApiSecurityScanner()
    findings = scanner.scan_directory(tmp_path)

    rl_findings = [f for f in findings if f.rule_id == "API-RATELIMIT-MISSING"]
    assert len(rl_findings) == 1
    assert rl_findings[0].severity == Severity.WARNING


def test_api_security_mass_assignment(tmp_path: Path):
    api_file = tmp_path / "crud.py"
    api_file.write_text(
        "def create_user_profile(request):\n"
        "    user = User.create(**request.json)\n"
        "    return user\n"
    )
    scanner = ApiSecurityScanner()
    findings = scanner.scan_directory(tmp_path)

    mass_findings = [f for f in findings if f.rule_id == "API-MASS-ASSIGNMENT"]
    assert len(mass_findings) == 1
    assert mass_findings[0].severity == Severity.ERROR


def test_api_security_clean_code_no_findings(tmp_path: Path):
    code_file = tmp_path / "utils.py"
    code_file.write_text(
        "def format_date(dt):\n"
        "    return dt.strftime('%Y-%m-%d')\n"
    )
    scanner = ApiSecurityScanner()
    findings = scanner.scan_directory(tmp_path)
    assert len(findings) == 0
