"""Security Bypasses and Linter Suppression Counter.

Detects when AI agents bypass quality gates by adding inline linter silencers
(# noqa, # type: ignore, # nosec) or introducing dangerous code patterns
(verify=False, shell=True, eval, exec).
Uses Tree-Sitter AST to avoid false positives on string literals and documentation.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import List, Optional

import tree_sitter
import tree_sitter_python

from guardrail.config import BypassesConfig
from guardrail.git_diff import DiffResult
from guardrail.models import Finding, Severity


class BypassesAnalyzer:
    """Detects linter suppressions and dangerous code patterns using AST and comment parsing."""

    def __init__(self, config: BypassesConfig):
        self.config = config
        self._language = tree_sitter.Language(tree_sitter_python.language())
        self._parser = tree_sitter.Parser(self._language)

    def is_exempt(self, file_path: str) -> bool:
        """Check if file path is exempt from bypass checks (e.g. test files)."""
        normalized = file_path.replace("\\", "/").strip("/")
        base_name = Path(file_path).name
        for pattern in self.config.exempt_paths:
            clean_pat = pattern.replace("\\", "/").strip("/")
            if fnmatch.fnmatch(normalized, clean_pat) or fnmatch.fnmatch(base_name, clean_pat):
                return True
        return False

    def _analyze_python_ast(
        self,
        file_path: str,
        code_bytes: bytes,
        diff_result: Optional[DiffResult] = None,
    ) -> List[Finding]:
        """Analyze Python source code using Tree-sitter AST."""
        tree = self._parser.parse(code_bytes)
        code_lines = code_bytes.decode("utf-8", errors="replace").splitlines()
        findings: List[Finding] = []

        def get_line_snippet(line_idx: int) -> str:
            if 0 <= line_idx < len(code_lines):
                return code_lines[line_idx].strip()
            return ""

        def is_line_eligible(line_1_indexed: int) -> bool:
            if diff_result is None:
                return True
            return diff_result.is_line_added(file_path, line_1_indexed)

        def traverse(node: tree_sitter.Node) -> None:
            line_num = node.start_point[0] + 1
            col = node.start_point[1]

            # 1. Check comments for linter suppressions
            if node.type == "comment":
                if is_line_eligible(line_num):
                    comment_text = node.text.decode("utf-8", errors="replace")
                    for supp in self.config.forbidden_suppressions:
                        if supp in comment_text:
                            findings.append(
                                Finding(
                                    rule_id="GUARD-BYPASS-001",
                                    analyzer="bypasses",
                                    severity=Severity.ERROR,
                                    message=(
                                        f"Linter/typechecker suppression '{supp}' detected. "
                                        f"AI coding agents must resolve lint and type errors rather than suppressing them."
                                    ),
                                    file_path=file_path,
                                    line_number=line_num,
                                    column=col,
                                    snippet=get_line_snippet(node.start_point[0]),
                                    details={"suppression": supp},
                                )
                            )
                            break

            # 2. Check call nodes for dangerous functions: eval, exec, os.system
            elif node.type == "call":
                if is_line_eligible(line_num):
                    fn_node = node.child_by_field_name("function")
                    if fn_node:
                        # Direct eval() or exec()
                        if fn_node.type == "identifier":
                            fn_name = fn_node.text.decode("utf-8", errors="replace")
                            if fn_name in ("eval", "exec"):
                                findings.append(
                                    Finding(
                                        rule_id="GUARD-SEC-003",
                                        analyzer="bypasses",
                                        severity=Severity.ERROR,
                                        message=f"Security hazard: Arbitrary code execution via {fn_name}() detected.",
                                        file_path=file_path,
                                        line_number=line_num,
                                        column=col,
                                        snippet=get_line_snippet(node.start_point[0]),
                                        details={"function": fn_name},
                                    )
                                )
                        # os.system(...)
                        elif fn_node.type == "attribute":
                            fn_text = fn_node.text.decode("utf-8", errors="replace")
                            if fn_text == "os.system":
                                findings.append(
                                    Finding(
                                        rule_id="GUARD-SEC-004",
                                        analyzer="bypasses",
                                        severity=Severity.WARNING,
                                        message="Security hazard: Use of os.system() is discouraged; use subprocess.run with argument list.",
                                        file_path=file_path,
                                        line_number=line_num,
                                        column=col,
                                        snippet=get_line_snippet(node.start_point[0]),
                                        details={"function": fn_text},
                                    )
                                )

            # 3. Check keyword arguments for verify=False and shell=True
            elif node.type == "keyword_argument":
                if is_line_eligible(line_num):
                    kw_text = node.text.decode("utf-8", errors="replace")
                    if kw_text.replace(" ", "") == "verify=False":
                        findings.append(
                            Finding(
                                rule_id="GUARD-SEC-001",
                                analyzer="bypasses",
                                severity=Severity.ERROR,
                                message="Security hazard: Disabled TLS/SSL certificate verification (verify=False) detected.",
                                file_path=file_path,
                                line_number=line_num,
                                column=col,
                                snippet=get_line_snippet(node.start_point[0]),
                                details={"argument": "verify=False"},
                            )
                        )
                    elif kw_text.replace(" ", "") == "shell=True":
                        findings.append(
                            Finding(
                                rule_id="GUARD-SEC-002",
                                analyzer="bypasses",
                                severity=Severity.ERROR,
                                message="Security hazard: subprocess call with shell=True creates command injection risk.",
                                file_path=file_path,
                                line_number=line_num,
                                column=col,
                                snippet=get_line_snippet(node.start_point[0]),
                                details={"argument": "shell=True"},
                            )
                        )

            for child in node.children:
                traverse(child)

        traverse(tree.root_node)
        return findings

    def _analyze_non_python(
        self,
        file_path: str,
        content: str,
        diff_result: Optional[DiffResult] = None,
    ) -> List[Finding]:
        """Fallback analysis for JS, TS, and other supported languages."""
        lines = content.splitlines()
        findings: List[Finding] = []

        inspect_lines: List[tuple[int, str]] = []
        if diff_result is not None:
            norm_path = file_path.replace("\\", "/")
            file_diff = None
            for p, fd in diff_result.files.items():
                if p.replace("\\", "/") == norm_path:
                    file_diff = fd
                    break
            if file_diff:
                for added in file_diff.added_lines:
                    inspect_lines.append((added.line_number, added.content))
            else:
                return []
        else:
            for idx, line in enumerate(lines):
                inspect_lines.append((idx + 1, line))

        for line_num, line_text in inspect_lines:
            # Check comment lines for suppressions
            stripped = line_text.strip()
            if stripped.startswith(("//", "/*", "*", "#")):
                for supp in self.config.forbidden_suppressions:
                    if supp in stripped:
                        findings.append(
                            Finding(
                                rule_id="GUARD-BYPASS-001",
                                analyzer="bypasses",
                                severity=Severity.ERROR,
                                message=f"Linter/typechecker suppression '{supp}' detected.",
                                file_path=file_path,
                                line_number=line_num,
                                column=line_text.find(supp),
                                snippet=stripped,
                                details={"suppression": supp},
                            )
                        )
                        break

        return findings

    def analyze_file(
        self,
        file_path: str,
        content: str | bytes,
        diff_result: Optional[DiffResult] = None,
    ) -> List[Finding]:
        """Analyze a file for linter suppressions and dangerous security patterns."""
        if not self.config.enabled:
            return []

        if self.is_exempt(file_path):
            return []

        p = Path(file_path)
        if p.suffix == ".py":
            code_bytes = content if isinstance(content, bytes) else content.encode("utf-8")
            return self._analyze_python_ast(file_path, code_bytes, diff_result=diff_result)
        else:
            code_text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
            return self._analyze_non_python(file_path, code_text, diff_result=diff_result)
