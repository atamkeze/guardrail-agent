# GuardRail-Agent 🛡️
> **CLI + CI/CD Drift Engine for AI-Assisted Codebases**  
> *Prevent AI coding agents from introducing hallucinated dependencies (slopsquatting), architectural boundary erosion, and security bypasses.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: >=3.11](https://img.shields.io/badge/Python->=3.11-blue.svg)](https://www.python.org/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-brightgreen.svg)](https://sarifweb.azurewebsites.net/)

---

## The Problem: The Hidden Failure Modes of AI Coding Agents

Autonomous and semi-autonomous AI coding agents (Claude Code, Cursor, Aider, GitHub Copilot Workspace) drastically accelerate development. However, they consistently introduce three dangerous failure patterns:

1. **Hallucinated Dependencies & Slopsquatting:**  
   LLMs frequently invent non-existent package names (e.g., `flask-jwt-auth-v2`, `fastapi-validation-utils`). Malicious actors monitor common LLM hallucinations and register them on PyPI containing remote access trojans or info-stealers (an attack known as **Slopsquatting**). When the AI agent or developer runs `pip install`, arbitrary code executes on the machine.
2. **Architectural Drift & Layer Erosion:**  
   AI agents lack holistic architectural awareness. When asked to "fetch user data on the checkout screen," an AI agent often bypasses domain services and directly imports the raw database driver or ORM inside a presentation controller, ruining Clean Architecture / Hexagonal / DDD boundaries.
3. **Security Bypasses & Quality Gate Evasion:**  
   When confronted with strict linters, typecheckers, or TLS warnings, AI agents take the path of least resistance: adding `# noqa: all`, `# type: ignore`, `// @ts-ignore`, disabling SSL certificate verification (`verify=False`), or invoking `subprocess(shell=True)`.

**GuardRail-Agent** acts as a zero-trust quality gate in local development and CI/CD pipelines to detect and halt these anti-patterns before code merges.

---

## Key Features

- **Diff-Aware Inspection:** Does not fail on existing legacy technical debt. Only analyzes files and lines newly modified in a git commit, staged area, or PR branch.
- **Asynchronous PyPI Registry Verification:** Validates newly introduced dependencies against PyPI concurrently with `httpx`. Catches non-existent packages (404), suspiciously new packages (< 30 days old), and typosquats (Levenshtein distance <= 2).
- **Tree-Sitter AST Architectural Boundary Checker:** Leverages `tree-sitter-python` to parse AST imports without executing code, enforcing strict layer rules (e.g., `domain` cannot import `infrastructure`).
- **AST-Based Linter Suppression Counter:** Uses AST to differentiate genuine code suppressions (`# noqa`, `# type: ignore`) and dangerous calls (`verify=False`, `shell=True`, `eval()`) from string literals or documentation.
- **Dual Reporting:** Generates human-friendly terminal tables and summaries with `rich`, plus industry-standard **SARIF 2.1.0** reports for direct integration with GitHub Advanced Security and GitLab SAST.

---

## Directory Layout

```text
guardrail-agent/
├── guardrail/
│   ├── __init__.py
│   ├── cli.py                     # Typer CLI entry points (check, scan, init, version)
│   ├── config.py                  # TOML loader and Pydantic models
│   ├── git_diff.py                # Diff parser and line/dependency modification tracker
│   ├── models.py                  # Core finding and scan summary data models
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── slopsquatting.py       # Asynchronous PyPI registry and typosquat checker
│   │   ├── architecture.py        # Tree-sitter import boundary checker
│   │   └── bypasses.py            # AST linter suppression and dangerous call detector
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── console.py             # Rich formatted terminal output
│   │   └── sarif.py               # GitHub Security SARIF 2.1.0 exporter
├── tests/
│   ├── test_git_diff.py
│   ├── test_slopsquatting.py
│   ├── test_architecture.py
│   ├── test_bypasses.py
│   └── test_cli.py
├── .drift-rules.toml              # Default policy file
├── pyproject.toml                 # Packaging & dependencies
└── README.md
```

---

## Installation

### From Source / Pip
```bash
git clone https://github.com/guardrail-agent/guardrail-agent.git
cd guardrail-agent
python -m pip install -e .
```

Requires Python >= 3.11.

---

## CLI Usage

### 1. Initialize Policy Configuration
Generate a `.drift-rules.toml` policy file in your repository:
```bash
guardrail init
```

### 2. Check Git Pull Requests or Working Tree (`check`)
Inspect only newly added or modified lines in git:
```bash
# Check unstaged + staged changes in working tree
guardrail check --diff

# Check staged commits (pre-commit)
guardrail check --staged

# Check PR changes against the main branch in CI/CD
guardrail check --base-ref origin/main --sarif results.sarif
```

### 3. Full Repository Scan (`scan`)
Audit the entire codebase:
```bash
guardrail scan .
guardrail scan src/ --fail-level warning
```

### 4. JSON Output
Emit machine-readable JSON for integration into custom internal tooling:
```bash
guardrail scan . --json
```

---

## Configuration (`.drift-rules.toml`)

GuardRail-Agent is configured declaratively via `.drift-rules.toml` in your repository root:

```toml
[general]
name = "Standard AI Drift & Guardrails Policy"
fail_on_severity = "error" # "error", "warning", or "info"
exclude_patterns = [
    ".git/**",
    ".venv/**",
    "dist/**",
    "build/**",
]

[slopsquatting]
enabled = true
check_registry = true
check_age = true
min_package_age_days = 30
min_monthly_downloads = 500
allowlist = ["pytest", "httpx", "internal-auth-sdk"]
blocklist = ["requestss", "urllib4"]

[architecture]
enabled = true

[architecture.layers]
domain = ["**/domain/**", "**/models/**"]
application = ["**/application/**", "**/services/**"]
infrastructure = ["**/infrastructure/**", "**/database/**"]
presentation = ["**/presentation/**", "**/api/**", "**/cli.py"]

[[architecture.forbidden_imports]]
source_layer = "domain"
disallowed_layers = ["infrastructure", "presentation", "application"]
reason = "Domain entities must have zero external architectural dependencies."

[[architecture.forbidden_imports]]
source_layer = "presentation"
disallowed_layers = ["infrastructure"]
reason = "Presentation layer cannot directly import raw database drivers."

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
]
dangerous_calls = [
    { pattern = 'verify\s*=\s*False', severity = "error", message = "Disabled TLS/SSL certificate verification detected." },
    { pattern = 'shell\s*=\s*True', severity = "error", message = "subprocess call with shell=True creates command injection risk." },
    { pattern = '\beval\s*\(', severity = "error", message = "Arbitrary code execution via eval() detected." },
    { pattern = '\bexec\s*\(', severity = "error", message = "Arbitrary code execution via exec() detected." },
]
exempt_paths = [
    "tests/**",
    "*_test.py",
    "test_*.py",
]
```

---

## Real-Life Workflows & CI/CD Integration

### 1. GitHub Actions CI/CD Gate
Add `.github/workflows/guardrail.yml` to automatically scan every Pull Request and publish security alerts directly onto GitHub's Code Scanning tab:

```yaml
name: GuardRail-Agent AI Gate

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main]

jobs:
  guardrail-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full history needed for base-ref diff

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install GuardRail-Agent
        run: pip install guardrail-agent

      - name: Run GuardRail PR Diff Inspection
        run: |
          guardrail check --base-ref origin/main --sarif guardrail.sarif

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guardrail.sarif
```

### 2. Pre-Commit Hook Integration
Prevent AI coding assistants from committing bad code locally by adding this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: guardrail-agent
        name: GuardRail AI Codebase Gate
        entry: guardrail check --staged
        language: python
        additional_dependencies: ["guardrail-agent"]
        always_run: true
        pass_filenames: false
```

### 3. Agentic Pair-Programming Guard
When using Cursor, Claude Code, or Aider:
```bash
# After the agent announces "I'm done with the task":
guardrail check --diff
```
If the agent hallucinated a library or took an architectural shortcut, GuardRail flags the exact line and rule violation so you can instruct the agent to fix it before committing.

---

## Running Tests

Run the full automated test suite with `pytest`:

```bash
pytest -v
```

Test coverage includes:
- Git unified diff parsing & line-level addition tracking
- Async PyPI 404 hallucination & package age threshold mocking with `respx`
- Tree-sitter AST layer boundary validation
- Comment suppression & dangerous call detection
- Typer CLI commands, error handling, JSON output, and SARIF 2.1.0 compliance

---

## License

MIT License. Designed and engineered for secure, drift-free AI software development.
