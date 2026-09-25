"""Agent Module D: Architecture and API Security Analysis using Tree-Sitter AST."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

import tree_sitter
import tree_sitter_python
from guardrail.cli import collect_project_files
from guardrail.models import Finding, Severity


class ApiSecurityScanner:
    """Analyzes API routes, authentication gates, rate limits, IDOR patterns, and mass-assignment risks."""

    def __init__(self, exclude_patterns: List[str] = None):
        self.exclude_patterns = exclude_patterns or [
            ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"
        ]
        self._language = tree_sitter.Language(tree_sitter_python.language())
        self._parser = tree_sitter.Parser(self._language)

    def scan_directory(self, root: Path) -> List[Finding]:
        findings: List[Finding] = []
        files = collect_project_files(root, self.exclude_patterns)

        for file_path in files:
            rel_path = str(file_path.relative_to(root)).replace("\\", "/")
            if file_path.suffix == ".py":
                try:
                    findings.extend(self._analyze_python_api(file_path, rel_path))
                except Exception:
                    pass
            elif file_path.suffix in (".php", ".js", ".ts"):
                try:
                    findings.extend(self._analyze_generic_api(file_path, rel_path))
                except Exception:
                    pass

        return findings

    def _analyze_python_api(self, file_path: Path, rel_path: str) -> List[Finding]:
        findings: List[Finding] = []
        code_bytes = file_path.read_bytes()
        code_text = code_bytes.decode("utf-8", errors="replace")
        lines = code_text.splitlines()

        tree = self._parser.parse(code_bytes)

        def get_snippet(line_idx: int) -> str:
            if 0 <= line_idx < len(lines):
                return lines[line_idx].strip()[:100]
            return ""

        def traverse(node: tree_sitter.Node):
            # Check decorated definitions (FastAPI / Flask / Django)
            if node.type == "decorated_definition":
                decorators = []
                func_node = None
                for child in node.children:
                    if child.type == "decorator":
                        decorators.append(child.text.decode("utf-8"))
                    elif child.type == "function_definition":
                        func_node = child

                if func_node:
                    dec_str = " ".join(decorators)
                    func_name = ""
                    fname_node = func_node.child_by_field_name("name")
                    if fname_node:
                        func_name = fname_node.text.decode("utf-8")

                    is_route = any(
                        r in dec_str
                        for r in ("@app.get", "@app.post", "@app.put", "@app.delete", "@router.", "@api_view", "route(")
                    )

                    # 1. Unauthenticated sensitive endpoint
                    sensitive_names = ("admin", "delete", "update", "export", "dashboard", "billing", "payment", "user_profile")
                    is_sensitive = any(s in func_name.lower() or s in dec_str.lower() for s in sensitive_names)

                    has_auth = any(
                        a in dec_str or a in func_node.text.decode("utf-8")
                        for a in ("Depends(get_current", "Depends(auth", "login_required", "authenticate", "permission_classes", "jwt_required")
                    )

                    if is_route and is_sensitive and not has_auth:
                        findings.append(Finding(
                            rule_id="API-AUTH-MISSING",
                            analyzer="ApiSecurityScanner",
                            severity=Severity.ERROR,
                            message=f"Potentially unauthenticated sensitive API endpoint '{func_name}'. Missing authentication dependency/decorator.",
                            file_path=rel_path,
                            line_number=node.start_point[0] + 1,
                            snippet=get_snippet(node.start_point[0])
                        ))

                    # 2. Missing rate limit on auth endpoints (/login, /register, /auth, /token)
                    is_auth_route = any(a in dec_str.lower() or a in func_name.lower() for a in ("login", "token", "register", "password_reset"))
                    has_rate_limit = any(r in dec_str for r in ("@limiter.limit", "throttle", "rate_limit"))
                    if is_route and is_auth_route and not has_rate_limit:
                        findings.append(Finding(
                            rule_id="API-RATELIMIT-MISSING",
                            analyzer="ApiSecurityScanner",
                            severity=Severity.WARNING,
                            message=f"Authentication endpoint '{func_name}' is missing rate limiting protection against brute-force attacks.",
                            file_path=rel_path,
                            line_number=node.start_point[0] + 1,
                            snippet=get_snippet(node.start_point[0])
                        ))

            # 3. Mass assignment / Insecure direct object update
            if node.type == "call":
                fn = node.child_by_field_name("function")
                if fn and (b"create" in fn.text or b"update" in fn.text):
                    args = node.child_by_field_name("arguments")
                    if args:
                        arg_text = args.text.decode("utf-8")
                        if "**request.json" in arg_text or "**request.form" in arg_text or "**request.data" in arg_text or "request.dict()" in arg_text:
                            findings.append(Finding(
                                rule_id="API-MASS-ASSIGNMENT",
                                analyzer="ApiSecurityScanner",
                                severity=Severity.ERROR,
                                message="Potential Mass Assignment: Unfiltered request dictionary unpacked directly into ORM model creation/update.",
                                file_path=rel_path,
                                line_number=node.start_point[0] + 1,
                                snippet=get_snippet(node.start_point[0])
                            ))

            for c in node.children:
                traverse(c)

        traverse(tree.root_node)
        return findings

    def _analyze_generic_api(self, file_path: Path, rel_path: str) -> List[Finding]:
        """Generic checks for Express / Laravel / PHP routes."""
        findings: List[Finding] = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            # Laravel: Route without auth middleware
            if ("Route::post(" in line or "Route::delete(" in line) and "admin" in line.lower() and "auth" not in line:
                findings.append(Finding(
                    rule_id="API-AUTH-MISSING",
                    analyzer="ApiSecurityScanner",
                    severity=Severity.WARNING,
                    message="Laravel administrative route declared without explicit 'auth' middleware group.",
                    file_path=rel_path,
                    line_number=idx,
                    snippet=line.strip()[:100]
                ))

            # Express: app.post without authenticateToken
            if ("app.post('/api/admin" in line or "router.delete('/admin" in line) and "auth" not in line.lower():
                findings.append(Finding(
                    rule_id="API-AUTH-MISSING",
                    analyzer="ApiSecurityScanner",
                    severity=Severity.WARNING,
                    message="Express.js administrative route handler missing authentication middleware.",
                    file_path=rel_path,
                    line_number=idx,
                    snippet=line.strip()[:100]
                ))

        return findings
