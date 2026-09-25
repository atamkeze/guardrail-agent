"""Tests for Codebase Profiler and Execution Planning."""

from pathlib import Path
from guardrail.agent.profiler import CodebaseProfiler


def test_profiler_detects_fastapi_and_python(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("fastapi>=0.100.0\nuvicorn>=0.20.0\nsqlalchemy>=2.0\n")
    app_file = tmp_path / "main.py"
    app_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    profiler = CodebaseProfiler()
    profile = profiler.profile_directory(tmp_path)

    assert "Python" in profile.languages
    assert "FastAPI" in profile.frameworks
    assert "main.py" in profile.entry_points
    assert "SQLAlchemy" in profile.database_layer


def test_profiler_detects_laravel_and_payment(tmp_path: Path):
    composer = tmp_path / "composer.json"
    composer.write_text('{"require": {"laravel/framework": "^11.0", "notchpay/notchpay-php": "^1.0"}}')
    artisan = tmp_path / "artisan"
    artisan.write_text("#!/usr/bin/env php\n")

    profiler = CodebaseProfiler()
    profile = profiler.profile_directory(tmp_path)

    assert "Laravel" in profile.frameworks
    assert profile.has_payment_processing is True
    assert "NotchPay" in profile.external_integrations


def test_profiler_detects_healthcare_and_financial(tmp_path: Path):
    health_file = tmp_path / "patient_records.py"
    health_file.write_text("# Clinical patient HIPAA compliance module\n")
    fin_file = tmp_path / "ledger.py"
    fin_file.write_text("# Bank account number and balance settlement\n")

    profiler = CodebaseProfiler()
    profile = profiler.profile_directory(tmp_path)

    assert profile.has_healthcare_data is True
    assert profile.has_financial_data is True


def test_profiler_execution_plan_weights(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("stripe>=5.0.0\nfastapi>=0.100.0\n")
    profiler = CodebaseProfiler()
    profile = profiler.profile_directory(tmp_path)
    plan = profiler.create_execution_plan(profile)

    # Because payment processing is detected, Secrets should have maximum weight
    sec_mod = next(m for m in plan.selected_modules if m.module_id == "module_b")
    assert sec_mod.priority == "MAXIMUM"
    assert sec_mod.weight == 1.0
    assert "Threat Model" in plan.reasoning_narrative or "prioritize" in plan.reasoning_narrative.lower()


def test_profiler_clean_repo_empty(tmp_path: Path):
    profiler = CodebaseProfiler()
    profile = profiler.profile_directory(tmp_path)
    plan = profiler.create_execution_plan(profile)

    assert len(plan.selected_modules) >= 5
    assert profile.has_payment_processing is False
