"""Configuration loader and schema models for GuardRail-Agent."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

import tomllib


class GeneralConfig(BaseModel):
    name: str = "Standard AI Drift & Guardrails Policy"
    fail_on_severity: str = Field(default="error", description="Minimum severity level that triggers non-zero exit code: info, warning, error")
    exclude_patterns: List[str] = Field(
        default_factory=lambda: [
            ".git/**",
            ".venv/**",
            "venv/**",
            "__pycache__/**",
            "*.egg-info/**",
            "dist/**",
            "build/**",
        ]
    )


class SlopsquattingConfig(BaseModel):
    enabled: bool = True
    min_package_age_days: int = 30
    min_monthly_downloads: int = 500
    check_age: bool = True
    check_registry: bool = True
    allowlist: List[str] = Field(default_factory=list)
    blocklist: List[str] = Field(default_factory=list)
    registry_url: str = "https://pypi.org/pypi/{package}/json"
    timeout_seconds: float = 5.0


class ForbiddenImportRule(BaseModel):
    source_layer: str
    disallowed_layers: List[str] = Field(default_factory=list)
    disallowed_modules: List[str] = Field(default_factory=list)
    reason: str = "Layer architectural boundary violation"


class ArchitectureConfig(BaseModel):
    enabled: bool = True
    layers: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "domain": ["**/domain/**", "**/models/**", "**/entities/**"],
            "application": ["**/application/**", "**/services/**", "**/use_cases/**"],
            "infrastructure": ["**/infrastructure/**", "**/repositories/**", "**/database/**", "**/clients/**"],
            "presentation": ["**/presentation/**", "**/controllers/**", "**/api/**", "**/cli.py", "**/reporters/**"],
        }
    )
    forbidden_imports: List[ForbiddenImportRule] = Field(default_factory=list)


class DangerousCallRule(BaseModel):
    pattern: str
    severity: str = "error"
    message: str = "Dangerous code pattern detected"


class BypassesConfig(BaseModel):
    enabled: bool = True
    max_new_suppressions: int = 0
    forbidden_suppressions: List[str] = Field(
        default_factory=lambda: [
            "# noqa",
            "# type: ignore",
            "# nosec",
            "# pragma: no cover",
            "// @ts-ignore",
            "/* eslint-disable",
            "// eslint-disable-next-line",
        ]
    )
    dangerous_calls: List[DangerousCallRule] = Field(
        default_factory=lambda: [
            DangerousCallRule(
                pattern=r"verify\s*=\s*False",
                severity="error",
                message="Disabled TLS/SSL certificate verification detected.",
            ),
            DangerousCallRule(
                pattern=r"shell\s*=\s*True",
                severity="error",
                message="subprocess call with shell=True creates command injection risk.",
            ),
            DangerousCallRule(
                pattern=r"\beval\s*\(",
                severity="error",
                message="Arbitrary code execution via eval() detected.",
            ),
            DangerousCallRule(
                pattern=r"\bexec\s*\(",
                severity="error",
                message="Arbitrary code execution via exec() detected.",
            ),
            DangerousCallRule(
                pattern=r"os\.system\s*\(",
                severity="warning",
                message="Use of os.system() is discouraged; use subprocess.run with argument list.",
            ),
        ]
    )
    exempt_paths: List[str] = Field(
        default_factory=lambda: [
            "tests/**",
            "*_test.py",
            "test_*.py",
        ]
    )


class GuardrailConfig(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    slopsquatting: SlopsquattingConfig = Field(default_factory=SlopsquattingConfig)
    architecture: ArchitectureConfig = Field(default_factory=ArchitectureConfig)
    bypasses: BypassesConfig = Field(default_factory=BypassesConfig)


DEFAULT_CONFIG_TOML = """# GuardRail-Agent Policy Configuration
# Defines architectural boundaries, slopsquatting guards, and security bypass rules.

[general]
name = "Standard AI Drift & Guardrails Policy"
fail_on_severity = "error"
exclude_patterns = [
    ".git/**",
    ".venv/**",
    "venv/**",
    "__pycache__/**",
    "*.egg-info/**",
    "dist/**",
    "build/**",
]

[slopsquatting]
enabled = true
min_package_age_days = 30
min_monthly_downloads = 500
check_age = true
check_registry = true
allowlist = []
blocklist = []
registry_url = "https://pypi.org/pypi/{package}/json"
timeout_seconds = 5.0

[architecture]
enabled = true

[architecture.layers]
domain = ["**/domain/**", "**/models/**", "**/entities/**"]
application = ["**/application/**", "**/services/**", "**/use_cases/**"]
infrastructure = ["**/infrastructure/**", "**/repositories/**", "**/database/**", "**/clients/**"]
presentation = ["**/presentation/**", "**/controllers/**", "**/api/**", "**/cli.py", "**/reporters/**"]

[[architecture.forbidden_imports]]
source_layer = "domain"
disallowed_layers = ["infrastructure", "presentation", "application"]
reason = "Domain entities must have zero external architectural dependencies."

[[architecture.forbidden_imports]]
source_layer = "application"
disallowed_layers = ["presentation"]
reason = "Application logic cannot depend on user interface or presentation layer."

[[architecture.forbidden_imports]]
source_layer = "presentation"
disallowed_layers = ["infrastructure"]
reason = "Presentation controllers should not directly import raw infrastructure/database drivers."

[bypasses]
enabled = true
max_new_suppressions = 0
forbidden_suppressions = [
    "# noqa",
    "# type: ignore",
    "# nosec",
    "# pragma: no cover",
    "// @ts-ignore",
    "/* eslint-disable",
    "// eslint-disable-next-line",
]
dangerous_calls = [
    { pattern = 'verify\\\\s*=\\\\s*False', severity = "error", message = "Disabled TLS/SSL certificate verification detected." },
    { pattern = 'shell\\\\s*=\\\\s*True', severity = "error", message = "subprocess call with shell=True creates command injection risk." },
    { pattern = '\\\\beval\\\\s*\\\\(', severity = "error", message = "Arbitrary code execution via eval() detected." },
    { pattern = '\\\\bexec\\\\s*\\\\(', severity = "error", message = "Arbitrary code execution via exec() detected." },
    { pattern = 'os\\\\.system\\\\s*\\\\(', severity = "warning", message = "Use of os.system() is discouraged; use subprocess.run with an argument list." },
]
exempt_paths = [
    "tests/**",
    "*_test.py",
    "test_*.py",
]
"""


def load_config(config_path: Path | str | None = None) -> GuardrailConfig:
    """Load configuration from a TOML file or fallback to default search paths."""
    resolved_path: Optional[Path] = None

    if config_path:
        p = Path(config_path)
        if p.is_file():
            resolved_path = p
        else:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
    else:
        # Check standard locations: current directory .drift-rules.toml, pyproject.toml
        candidates = [
            Path(".drift-rules.toml"),
            Path("drift-rules.toml"),
            Path("guardrail.toml"),
            Path(".guardrail.toml"),
        ]
        for candidate in candidates:
            if candidate.is_file():
                resolved_path = candidate
                break

    if resolved_path is None:
        # Check pyproject.toml for [tool.guardrail]
        pyproject = Path("pyproject.toml")
        if pyproject.is_file():
            try:
                with open(pyproject, "rb") as f:
                    data = tomllib.load(f)
                tool_config = data.get("tool", {}).get("guardrail")
                if tool_config:
                    return GuardrailConfig.model_validate(tool_config)
            except Exception:
                pass
        return GuardrailConfig()

    with open(resolved_path, "rb") as f:
        data = tomllib.load(f)

    return GuardrailConfig.model_validate(data)
