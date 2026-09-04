# GuardRail-Agent: Portfolio Case Study & Resume Presentation

**Author:** Rock Atamkeze
**Roles:** Fullstack Software Engineer | AI Engineer | Ethical Hacker & AI Security Specialist
**Repository:** [https://github.com/atamkeze/guardrail-agent](https://github.com/atamkeze/guardrail-agent)
**Tech Stack:** Python 3.13, Tree-Sitter AST, Model Context Protocol (MCP), Typer, Rich, httpx (async), Pydantic v2, SARIF 2.1.0, Pytest, Git Engine

---

## 1. Executive Summary (Portfolio Showcase)

**GuardRail-Agent** is an open-source, dual-mode developer security platform and CI/CD quality gate designed to prevent autonomous AI coding assistants (Claude Code, Cursor, Antigravity, Windsurf, Copilot, Codex) from introducing software supply chain vulnerabilities, architectural degradation, and security bypasses into production codebases.

Operating in a **"Shift-Left" Dual Mode**, GuardRail functions as:

1. **An In-IDE Model Context Protocol (MCP) Server:** Allows AI agents in Cursor, Claude Code, and Antigravity to self-audit proposed dependencies and code diffs in memory *before* writing files to disk.
2. **A Deterministic CI/CD Gate:** Evaluates git diffs in pre-commit and GitHub Actions pipelines, preventing pull requests from merging if they violate defined layer boundaries or introduce unverified packages, and exports OASIS SARIF 2.1.0 reports directly into GitHub Advanced Security.

---

## 2. The Problem Statement (The Attack Surface of AI Codebases)

The rapid adoption of AI coding agents has introduced three critical, widespread failure modes that traditional static analyzers and linters fail to catch:

1. **Slopsquatting (Hallucination Squatting):** LLMs regularly hallucinate non-existent libraries (e.g., `flask-jwt-auth-v2`). Malicious actors monitor LLM hallucination benchmarks, register these names on PyPI/npm, and inject remote-access malware into setup scripts. Running `pip install` results in immediate remote code execution.
2. **Architectural Drift & Layer Erosion:** AI assistants optimize for localized code syntax rather than macro-architectural contracts. When asked to implement a UI feature, an AI agent often bypasses domain services and imports raw database drivers directly into presentation controllers, destroying Clean Architecture / Hexagonal boundaries.
3. **Silent Security & Quality Evasion:** When confronted with typing or linting errors, AI assistants frequently take the path of least resistance: injecting `# noqa`, `# type: ignore`, `// @ts-ignore`, disabling TLS certificate verification (`verify=False`), or invoking shell execution (`shell=True`, `eval()`).

---

## 3. Engineering & Technical Architecture

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           GuardRail-Agent Architecture                           │
│                                                                                  │
│   [ Developer Workspace ]                    [ CI/CD & Security Gate ]           │
│   Cursor / Claude Code / Antigravity         GitHub Actions / GitLab CI / Git    │
│            │                                                │                    │
│            ▼ (JSON-RPC stdio)                               ▼ (CLI Subcommands)  │
│   ┌────────────────────────────────┐       ┌────────────────────────────────┐    │
│   │ Native FastMCP Server          │       │ Diff-Aware CLI Engine          │    │
│   │ • verify_dependencies()        │       │ • guardrail check --diff       │    │
│   │ • audit_code_drift()           │       │ • guardrail check --staged     │    │
│   │ • scan_current_git_diff()      │       │ • guardrail scan [dir]         │    │
│   └──────────────┬─────────────────┘       └──────────────┬─────────────────┘    │
│                  │                                        │                      │
│                  └───────────────────┬────────────────────┘                      │
│                                      ▼                                           │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │                        Core Analytical Engines                           │   │
│   │                                                                          │   │
│   │  [Slopsquatting Engine]      [Tree-Sitter AST]      [Bypass Inspector]   │   │
│   │  • Async PyPI Registry       • Layer Boundaries     • Comment AST Nodes  │   │
│   │  • Age Threshold (<30d)      • Clean Arch Enforcer  • Dangerous Calls    │   │
│   │  • Levenshtein Typosquats    • Relative Imports     • eval / verify=False│   │
│   └──────────────────────────────────┬───────────────────────────────────────┘   │
│                                      ▼                                           │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │                        Dual Reporting System                             │   │
│   │  • Rich Terminal UI (Color-coded tables, status panels, diagnostics)      │   │
│   │  • OASIS SARIF v2.1.0 Exporter (Native GitHub Code Scanning integration) │   │
│   └──────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Key Technical Innovations:

- **Diff-Aware Inspection (`git diff -U0`):** Indexes exact added/modified line numbers in the working tree, allowing immediate enterprise adoption on legacy codebases without blocking on historic technical debt.
- **Tree-Sitter Concrete Syntax Tree (CST) Traversal:** Performs deep AST parsing using `tree-sitter-python` without executing code, distinguishing genuine comment suppressions and call expressions from string literals and docstrings to eliminate false positives.
- **Concurrent Async Registry Verification:** Leverages `httpx.AsyncClient` with an `asyncio.Semaphore(10)` rate limiter to query PyPI JSON APIs asynchronously, evaluating release age, metadata, and edit-distance typosquats.
- **OASIS SARIF 2.1.0 Compliance:** Directly maps rule violations (`GUARD-SLOP-001`, `GUARD-ARCH-001`, `GUARD-SEC-001`) into the standardized SARIF format consumed by GitHub Advanced Security and GitLab SAST.

---

## 4. Key Performance & Quality Metrics

- **Test Suite:** 32 automated unit and integration tests (100% pass rate) covering mock PyPI 404s with `respx`, AST import traversal, git diff parsing, CLI commands, and MCP tool endpoints.
- **Execution Speed:** Full git diff scan in `< 500ms`; full repository audit with async registry checks in `< 1.2s`.
- **False Positive Elimination:** 0% false positives on docstring text and configuration files via Tree-Sitter AST node discrimination.

---

## 5. Ready-to-Use CV / Resume Content

### Option A: Professional Experience / Project Section (Bullet Points)

**GuardRail-Agent — Lead Architect & Creator** | *Python, Tree-Sitter, MCP, DevSecOps, AppSec* | [GitHub Link]

- Architected and released an open-source AI security drift engine and native Model Context Protocol (MCP) server preventing AI coding assistants from introducing hallucinated dependencies (slopsquatting) and architectural erosion.
- Engineered a high-throughput, async registry analyzer using `httpx` and `asyncio` that audits dependencies against PyPI in real-time, detecting 404 hallucinated packages, newly registered supply-chain risks (< 30 days old), and typosquatting attacks via Levenshtein distance algorithms.
- Built an AST-based architectural layer boundary enforcer using `tree-sitter-python` to inspect import statements and enforce Clean Architecture / DDD rules across domain, application, infrastructure, and presentation layers.
- Designed an AST comment and call inspector eliminating false positives on documentation and string literals while catching silent linter suppressions (`# type: ignore`, `# noqa`) and dangerous security patterns (`verify=False`, `shell=True`, `eval()`).
- Developed a dual-mode workflow featuring an in-IDE MCP server for Claude Code, Cursor, and Google Antigravity, alongside a deterministic CI/CD CLI gate exporting OASIS SARIF 2.1.0 security annotations into GitHub Advanced Security.
- Authored a comprehensive automated test suite with 32 unit and integration tests using `pytest`, `pytest-asyncio`, and `respx`.

---

### Option B: Concise One-Paragraph Project Summary

> **GuardRail-Agent (Lead Architect & Security Researcher):** Designed and developed an open-source AI security gatekeeper and native Model Context Protocol (MCP) server that halts hallucinated dependency attacks ("slopsquatting"), architectural layer drift, and silent security bypasses generated by AI coding assistants (Cursor, Claude Code, Antigravity, Copilot). Built with Python 3.13, Tree-Sitter AST parsing, async PyPI verification (`httpx`), and standard SARIF 2.1.0 output for GitHub Advanced Security, enabling developers to shift security left into the AI pairing loop.

---

## 6. Interview "Elevator Pitch" (30–60 Seconds)

> *"With over 40% of code now being drafted by AI coding assistants, I identified a dangerous new attack vector called **Slopsquatting**—where LLMs hallucinate non-existent package names, and attackers pre-register them on PyPI with malware. To solve this, I designed and built **GuardRail-Agent**.*
>
> *GuardRail-Agent is an open-source, dual-mode security engine. In the IDE, it acts as a native **Model Context Protocol (MCP) server** that lets tools like Cursor, Claude Code, and Google Antigravity self-audit proposed packages and code diffs before saving them to disk. In CI/CD, it acts as a diff-aware gatekeeper using **Tree-Sitter AST parsing** to enforce Clean Architecture boundaries and block silent bypasses like `# type: ignore` and `verify=False`, publishing findings directly to GitHub Security via SARIF 2.1.0.*
>
> *This project allowed me to combine my fullstack software engineering background, my work with LLM agent toolchains, and my offensive security mindset to solve a real-world supply chain vulnerability."*

---

## 7. Core Competencies Demonstrated

| Domain                                      | Core Skills & Technologies Demonstrated                                                                                                                                    |
| :------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Software Architecture & Fullstack** | Clean Architecture, Domain-Driven Design (DDD), Modular Packaging, Python 3.13, Pydantic v2, Typer CLI, Rich UI.                                                           |
| **AI Engineering & LLM Toolchains**   | Model Context Protocol (MCP), FastMCP, Agent Self-Auditing, Prompt Engineering, Agentic Tool Design (Cursor, Claude Code, Antigravity).                                    |
| **Ethical Hacking & AI Security**     | Software Supply Chain Security, Slopsquatting / Hallucination Squatting Threat Modeling, Typosquatting Heuristics, AST-Based Code Analysis, TLS/SSL Enforcement.           |
| **DevSecOps & CI/CD**                 | Git Unified Diff Engine (`-U0`), GitHub Actions Workflows, Pre-Commit Hooks, OASIS SARIF v2.1.0 Standard, Automated Testing (`pytest`, `pytest-asyncio`, `respx`). |
