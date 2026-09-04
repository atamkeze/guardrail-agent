# GuardRail-Agent 🛡️
> **CLI + CI/CD Drift Engine & Native MCP Server for AI-Assisted Codebases**  
> *Prevent AI coding agents from introducing hallucinated dependencies (slopsquatting), architectural boundary erosion, and security bypasses.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: >=3.11](https://img.shields.io/badge/Python->=3.11-blue.svg)](https://www.python.org/)
[![MCP: 2.1+](https://img.shields.io/badge/MCP-Native%20Server-blueviolet.svg)](https://modelcontextprotocol.io/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-brightgreen.svg)](https://sarifweb.azurewebsites.net/)

---

## The Problem: The Hidden Failure Modes of AI Coding Agents

Autonomous and semi-autonomous AI coding agents (Claude Code, Cursor, Windsurf, Aider, GitHub Copilot) drastically accelerate software delivery. However, they consistently introduce three dangerous failure patterns:

1. **Hallucinated Dependencies & Slopsquatting:**  
   LLMs frequently invent non-existent package names (e.g., `flask-jwt-auth-v2`, `fastapi-validation-utils`). Malicious actors monitor common LLM hallucinations and register them on PyPI or npm containing remote access trojans or info-stealers (an attack known as **Slopsquatting**). When the AI agent or developer runs `pip install`, arbitrary code executes on the machine.
2. **Architectural Drift & Layer Erosion:**  
   AI agents lack holistic architectural awareness. When asked to "fetch user data on the checkout screen," an AI agent often bypasses domain services and directly imports the raw database driver or ORM inside a presentation controller, ruining Clean Architecture / Hexagonal / DDD boundaries.
3. **Security Bypasses & Quality Gate Evasion:**  
   When confronted with strict linters, typecheckers, or TLS warnings, AI agents take the path of least resistance: adding `# noqa: all`, `# type: ignore`, `// @ts-ignore`, disabling SSL certificate verification (`verify=False`), or invoking `subprocess(shell=True)`.

---

## Dual-Mode "Shift-Left" Architecture

GuardRail-Agent operates in two complementary modes:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        "Shift-Left" Dual Mode                          │
│                                                                        │
│   [Mode 1: Native MCP Server]           [Mode 2: Deterministic Gate]   │
│   Active inside Cursor / Claude Code     Active in CI/CD & Pre-commit  │
│                                                                        │
│   AI Agent self-audits before writing:  Independent CI pipeline check: │
│   - verify_dependencies(...)            - guardrail check --diff       │
│   - audit_code_drift(...)               - guardrail check --staged     │
│   - scan_current_git_diff()             - Upload SARIF to GitHub Sec   │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Native MCP Server (Interactive Guard):** Allows AI coding agents in Cursor, Claude Code, and Windsurf to self-audit proposed dependencies and code before writing files or committing changes.
2. **Deterministic CI/CD Gate (Independent Watchdog):** Runs in pre-commit hooks and GitHub Actions PR checks, generating SARIF 2.1.0 alerts to block pull requests if violations slip through.

---

## Directory Layout

```text
guardrail-agent/
├── guardrail/
│   ├── __init__.py
│   ├── cli.py                     # Typer CLI entry points (check, scan, init, mcp serve)
│   ├── config.py                  # TOML loader and Pydantic models
│   ├── git_diff.py                # Diff parser and line/dependency modification tracker
│   ├── models.py                  # Core finding and scan summary data models
│   ├── server/
│   │   ├── __init__.py
│   │   └── mcp_server.py          # Native Model Context Protocol (MCP) server
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
│   ├── test_cli.py
│   └── test_mcp_server.py
├── .drift-rules.toml              # Default policy file
├── pyproject.toml                 # Packaging & dependencies
├── GUARDRAIL_WORKFLOW_REPORT.md   # Living progress log & multi-language guide
└── README.md
```

---

## Installation

```bash
git clone https://github.com/atamkeze/guardrail-agent.git
cd guardrail-agent
python -m pip install -e .
```

Requires Python >= 3.11.

---

## Model Context Protocol (MCP) Server Setup

GuardRail-Agent provides a native MCP server with stdio transport.

### Adding to Claude Code / Cursor / Windsurf

Add the following to your MCP configuration file (e.g. `claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "guardrail": {
      "command": "python",
      "args": ["-m", "guardrail.server.mcp_server"]
    }
  }
}
```

Or if installed in a dedicated virtual environment:
```json
{
  "mcpServers": {
    "guardrail": {
      "command": "C:/Python/Projects/guardrail-agent/.venv/Scripts/guardrail-mcp.exe"
    }
  }
}
```

### Exposed MCP Tools

The AI assistant automatically accesses three dedicated tools:

1. **`verify_dependencies(manifest_content: str, manifest_type: str = "requirements.txt")`**  
   Audits dependencies before installing. Returns hallucinated (404) packages, freshly registered packages (< 30 days old), and typosquat warnings.
2. **`audit_code_drift(file_path: str, source_code: str)`**  
   Evaluates proposed Python code before saving to disk. Detects layer boundary violations according to `.drift-rules.toml`, banned calls (`verify=False`, `shell=True`, `eval`), and linter suppressions (`# noqa`, `# type: ignore`).
3. **`scan_current_git_diff()`**  
   Performs a full audit across all uncommitted working tree modifications in the local git repository.

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

### 4. Run MCP Server from CLI
```bash
guardrail mcp serve
# or directly:
guardrail-mcp
```

---

## Configuration (`.drift-rules.toml`)

```toml
[general]
name = "Standard AI Drift & Guardrails Policy"
fail_on_severity = "error"
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

## CI/CD Workflow Integration

### GitHub Actions PR Gate
Create `.github/workflows/guardrail.yml`:

```yaml
name: GuardRail-Agent CI Gate

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
          fetch-depth: 0

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

---

## Running Tests

Run the complete test suite with `pytest`:

```bash
pytest -v
```

All 32 tests verify:
- Unified git diff parsing and line-level addition tracking
- Async PyPI 404 hallucination & package age threshold mocking with `respx`
- Tree-sitter AST layer boundary validation
- Comment suppression & dangerous call AST node checking
- Typer CLI commands, error handling, JSON output, and SARIF 2.1.0 compliance
- Native MCP Server tools (`verify_dependencies`, `audit_code_drift`, `scan_current_git_diff`)

---

## Author & Security Research

Engineered by **Atam Keze**  
*Fullstack Software Engineer | AI Engineer | Ethical Hacking & AI Security Specialist*

- **GitHub:** [@atamkeze](https://github.com/atamkeze)
- **Repository:** [https://github.com/atamkeze/guardrail-agent](https://github.com/atamkeze/guardrail-agent)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
