# GuardRail-Agent: Living Architecture & Workflow Report 🛡️

*A living document tracking progress, architectural rationale, real-life workflows, and cross-language applicability.*

---

## 1. Executive Overview

**GuardRail-Agent** is a developer tool, CI/CD quality gate, and native Model Context Protocol (MCP) server designed to safeguard codebases against the three primary risks introduced by modern AI coding assistants (Claude Code, Cursor, Windsurf, Aider, GitHub Copilot):

1. **Slopsquatting & Dependency Hallucination:** LLMs frequently invent non-existent package names. Attackers register these packages on registries with malicious payloads. GuardRail verifies package existence, release age, and typosquatting risk before packages can be installed.
2. **Architectural Drift:** AI agents lack macro-architectural context and routinely violate Clean Architecture, Hexagonal, or Domain-Driven Design (DDD) boundaries (e.g., importing raw database drivers directly into domain models or presentation controllers).
3. **Security Bypasses & Quality Evasion:** When confronted with lint or type errors, AI assistants often take the path of least resistance by adding `# noqa`, `# type: ignore`, `// @ts-ignore`, disabling SSL certificate verification (`verify=False`), or using dangerous shell invocation (`shell=True`, `eval()`).

GuardRail operates in a **Dual-Mode "Shift-Left" Architecture**:
- **Interactive MCP Server:** Integrated directly into Cursor, Claude Code, or Windsurf so the agent can self-audit proposed dependencies and code diffs before saving them to disk.
- **Deterministic CI/CD Gate:** Runs on pull requests, parses git diffs, outputs terminal reports, and exports **SARIF 2.1.0** alerts directly into GitHub Security / Code Scanning.

---

## 2. Cross-Language Applicability: Is This Only for Python or All Programmers (e.g., PHP, TS, Go)?

> **Short Answer:** The risks GuardRail solves are **universal across ALL programming languages**. While the current implementation includes deep Python parsing (via `tree-sitter-python` and PyPI), the architecture was deliberately built with language-agnostic abstractions so that **PHP, JavaScript/TypeScript, Go, Rust, and Java** ecosystems can be plugged in seamlessly.

### A. Ecosystem Comparison: The AI Failure Modes Across Languages

| Failure Mode | Python Ecosystem | PHP (Composer/Packagist) | JavaScript / TypeScript (npm) | Go (Go Modules) |
| :--- | :--- | :--- | :--- | :--- |
| **Slopsquatting / Hallucinations** | AI invents `flask-jwt-auth-v2` → attacker registers it on PyPI. | AI invents `laravel-jwt-guard-v3` or `symfony-uuid-helper` → attacker registers on **Packagist**. | AI invents `express-jwt-permissions` or `react-hook-utilities` → attacker registers on **npm**. | AI invents non-existent GitHub module repository URLs in `go.mod`. |
| **Architectural Drift** | Domain layer imports SQLAlchemy `db_conn` directly. | Domain Entity imports Laravel's `DB::table()` or Symfony `EntityManager` directly into business logic. | React presentation component imports Prisma DB client directly in client-side code. | Core business package imports external HTTP handler or SQL driver directly. |
| **Linter / Quality Suppressions** | `# noqa`, `# type: ignore`, `# nosec` | `@` operator (error suppression), `// @phpstan-ignore-line`, `// phpcs:ignore` | `// @ts-ignore`, `/* eslint-disable */`, `// eslint-disable-next-line` | `// nolint:errcheck`, `// nolint:gosec` |
| **Dangerous Security Bypasses** | `verify=False` (disabled TLS), `shell=True`, `eval()` | `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false)`, `exec()`, `shell_exec()`, `eval()` | `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`, `child_process.exec()`, `eval()` | `InsecureSkipVerify: true` in `tls.Config`, unescaped `os/exec` commands. |

### B. Why GuardRail-Agent's Core Architecture is Inherently Multi-Language

1. **Tree-Sitter is Polyglot by Design:**  
   Unlike Python's built-in `ast` module, **Tree-Sitter** was chosen specifically because it supports over 40 programming languages with identical concrete syntax tree traversal APIs (`tree-sitter-php`, `tree-sitter-typescript`, `tree-sitter-javascript`, `tree-sitter-go`). Adding PHP or TypeScript to GuardRail only requires loading the corresponding language grammar and querying import statements (`use App\Models\User;` in PHP or `import { db } from './db'` in TS).
2. **Registry Adapters are Pluggable:**  
   The slopsquatting analyzer's query engine is decoupled:
   - **Python:** `https://pypi.org/pypi/{package}/json`
   - **PHP:** `https://repo.packagist.org/p2/{vendor}/{package}.json`
   - **JavaScript/TypeScript:** `https://registry.npmjs.org/{package}`
   - **Rust:** `https://crates.io/api/v1/crates/{package}`
3. **Multi-Language Diff & Suppression Engines:**  
   - `guardrail.git_diff` parses unified git diffs regardless of whether the modified file is `.py`, `.php`, `.ts`, or `.go`.
   - `guardrail.analyzers.bypasses` already contains language-neutral suppression matching (`// @ts-ignore`, `/* eslint-disable */`, `# noqa`) and can easily match PHP's `@phpstan-ignore` or `CURLOPT_SSL_VERIFYPEER => false`.

---

## 3. Implemented Components & Real-Life Workflow Applications

### 1. Configuration Engine (`guardrail/config.py`)
- **How It Works:** Loads `.drift-rules.toml` using Python 3.11's standard `tomllib` and validates via Pydantic v2 schemas. Configures slopsquatting allowlists/blocklists, architectural layer glob definitions, and banned call expressions.
- **Real-Life Value:** Zero-code policy definition. Security teams commit `.drift-rules.toml` into the repository root; all developers, CI gates, and AI agents automatically adhere to the same declarative security contract.

### 2. Diff-Aware Engine (`guardrail/git_diff.py`)
- **How It Works:** Executes `git diff -U0` against staged commits, unstaged working trees, or target branches (`origin/main...HEAD`). Builds an exact index of newly added line numbers and extracts modified package dependencies.
- **Real-Life Value:** Prevents blocking pull requests due to historic technical debt. Large enterprise repositories can immediately adopt GuardRail without having to clean up years of pre-existing linter warnings or architectural flaws.

### 3. Slopsquatting Analyzer (`guardrail/analyzers/slopsquatting.py`)
- **How It Works:** Concurrently queries PyPI via `httpx.AsyncClient` with an `asyncio.Semaphore(10)` rate limiter. Emits `GUARD-SLOP-001` (404 hallucination), `GUARD-SLOP-002` (newly registered package < 30 days old), and `GUARD-SLOP-003` (typosquatting edit distance against top 25 popular packages).
- **Real-Life Value:** Stops remote code execution supply-chain attacks *before* `pip install` or Docker image builds are executed.

### 4. Tree-Sitter Architectural Boundary Checker (`guardrail/analyzers/architecture.py`)
- **How It Works:** Uses Tree-Sitter AST parsing to map files to configured architectural layers (`domain`, `application`, `infrastructure`, `presentation`) and inspects import statements. Flags forbidden cross-layer imports (`GUARD-ARCH-001`) and restricted modules (`GUARD-ARCH-002`).
- **Real-Life Value:** Stops AI agents from eroding Clean Architecture / DDD patterns by preventing raw database queries or presentation controllers from leaking into pure business logic.

### 5. AST-Based Linter Suppression & Security Inspector (`guardrail/analyzers/bypasses.py`)
- **How It Works:** Uses AST comment nodes, call nodes, and keyword arguments to detect inline linter silencers (`# noqa`, `# type: ignore`) and high-risk security calls (`verify=False`, `shell=True`, `eval()`, `exec()`, `os.system()`). Because it inspects AST nodes, string literals in docstrings or configs are never falsely flagged.
- **Real-Life Value:** Enforces quality standards. Forces AI agents to fix typing issues rather than hiding them under `# type: ignore`.

### 6. Reporters: Rich Console & SARIF 2.1.0 (`guardrail/reporters/`)
- **How It Works:** Renders color-coded Rich terminal tables with exact `file:line:col` locations, error badges, and code snippets. Also exports full OASIS SARIF 2.1.0 JSON reports.
- **Real-Life Value:** Direct integration with **GitHub Advanced Security / Code Scanning** tab and pull request annotations.

### 7. Native Model Context Protocol (MCP) Server (`guardrail/server/mcp_server.py`)
- **How It Works:** Exposes three native MCP tools over standard stdio transport:
  1. `verify_dependencies(manifest_content, manifest_type)`: Audits proposed packages for hallucinations and age warnings before installation.
  2. `audit_code_drift(file_path, source_code)`: Audits proposed code in memory before the file is written to disk.
  3. `scan_current_git_diff()`: Checks all uncommitted changes in the working directory.
- **Real-Life Value:** Enables a true "Shift-Left" workflow. AI coding assistants running in Cursor, Claude Code, or Windsurf can self-audit their code in real time and fix hallucinations before the developer even inspects the diff.

---

## 4. Test Suite Verification

The project includes **32 automated tests** across 6 test modules:

```text
tests/test_architecture.py       5 passed (layer mapping, AST imports, relative imports, diff filtering)
tests/test_bypasses.py           4 passed (AST comments, dangerous calls, exempt paths, diff mode)
tests/test_cli.py                6 passed (version, init, clean scan, violation exit code, SARIF, JSON)
tests/test_git_diff.py           4 passed (unified diff parser, line tracking, dependency extractor)
tests/test_mcp_server.py         5 passed (verify_dependencies, pyproject, audit_code_drift, git diff)
tests/test_slopsquatting.py      8 passed (Levenshtein typosquats, allowlists, blocklists, 404s, package age)
------------------------------------------------------------------------------------------------------
Total: 32 passed in ~24 seconds
```

---

## 5. Quick Reference: MCP Server Configuration for IDEs

Add this to your IDE's MCP configuration (`.cursor/mcp.json`, Claude Desktop config, or Windsurf settings):

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

Or run directly via CLI:
```bash
guardrail mcp serve
# or
guardrail-mcp
```

---

## 6. Roadmap: Multi-Language Expansion Plan

1. **PHP / Composer Extension:**
   - Add Packagist JSON API endpoint (`https://repo.packagist.org/p2/{vendor}/{package}.json`).
   - Add `composer.json` dependency parser.
   - Integrate `tree-sitter-php` for namespace/`use` import validation and `@` / `@phpstan-ignore` detection.
2. **TypeScript & JavaScript (Node/npm):**
   - Add npm registry API endpoint (`https://registry.npmjs.org/{pkg}`).
   - Add `package.json` dependency parser.
   - Integrate `tree-sitter-typescript` for ESM/CommonJS import boundaries and `// @ts-ignore` detection.
3. **Go Modules:**
   - Add Go proxy API endpoint (`https://proxy.golang.org/`).
   - Parse `go.mod` files.
   - Enforce Go package import restrictions and `// nolint` detections.
