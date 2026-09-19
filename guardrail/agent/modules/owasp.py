"""Agent module for OWASP Top 10 Static Analysis (Tree-Sitter AST based)."""

import tree_sitter
import tree_sitter_python
from pathlib import Path
from typing import List

from guardrail.cli import collect_project_files
from guardrail.models import Finding, Severity

class OwaspScanner:
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
            if file_path.suffix == ".py":
                try:
                    code_bytes = file_path.read_bytes()
                    rel_path = str(file_path.relative_to(root)).replace("\\", "/")
                    findings.extend(self.analyze_file(rel_path, code_bytes))
                except Exception:
                    continue

        return findings

    def analyze_file(self, rel_path: str, code_bytes: bytes) -> List[Finding]:
        tree = self._parser.parse(code_bytes)
        findings: List[Finding] = []
        code_lines = code_bytes.decode("utf-8", errors="replace").splitlines()

        def get_line_snippet(line_idx: int) -> str:
            if 0 <= line_idx < len(code_lines):
                return code_lines[line_idx].strip()[:100]
            return ""

        def traverse(node: tree_sitter.Node):
            if node.type == "call":
                function_name_node = node.child_by_field_name("function")
                if function_name_node:
                    func_name = function_name_node.text.decode("utf-8")
                    
                    # 1. SQL Injection (A03:2021-Injection)
                    if "execute" in func_name or "query" in func_name:
                        args_node = node.child_by_field_name("arguments")
                        if args_node:
                            for arg in args_node.children:
                                if arg.type in ("string", "binary_operator"):
                                    has_interp = False
                                    for sub in arg.children:
                                        if sub.type == "interpolation":
                                            has_interp = True
                                            break
                                    
                                    is_concat = False
                                    if arg.type == "binary_operator":
                                        op = arg.child_by_field_name("operator")
                                        if op and op.text == b"+":
                                            is_concat = True

                                    if has_interp or is_concat:
                                        findings.append(Finding(
                                            rule_id="OWASP-A03-SQLI",
                                            analyzer="OwaspScanner",
                                            severity=Severity.ERROR,
                                            message="Potential SQL Injection: String formatting or concatenation detected in database query. Use parameterized queries instead.",
                                            file_path=rel_path,
                                            line_number=node.start_point[0] + 1,
                                            snippet=get_line_snippet(node.start_point[0])
                                        ))

                    # 2. Command Injection (A03:2021-Injection)
                    if "subprocess" in func_name or func_name in ("os.system", "os.popen"):
                        args_node = node.child_by_field_name("arguments")
                        shell_true = False
                        if args_node:
                            for arg in args_node.children:
                                if arg.type == "keyword_argument":
                                    name = arg.child_by_field_name("name")
                                    val = arg.child_by_field_name("value")
                                    if name and name.text == b"shell" and val and val.text == b"True":
                                        shell_true = True
                        
                        if shell_true or func_name in ("os.system", "os.popen"):
                            findings.append(Finding(
                                rule_id="OWASP-A03-CMDI",
                                analyzer="OwaspScanner",
                                severity=Severity.ERROR,
                                message="Potential Command Injection: Execution of arbitrary system commands detected. Avoid shell=True.",
                                file_path=rel_path,
                                line_number=node.start_point[0] + 1,
                                snippet=get_line_snippet(node.start_point[0])
                            ))

                    # 3. Insecure Deserialization (A08:2021-Software and Data Integrity Failures)
                    if "pickle.loads" in func_name or "yaml.load" in func_name:
                        is_safe = False
                        args_node = node.child_by_field_name("arguments")
                        if "yaml.load" in func_name and args_node:
                            for arg in args_node.children:
                                if arg.type == "keyword_argument":
                                    val = arg.child_by_field_name("value")
                                    if val and b"SafeLoader" in val.text:
                                        is_safe = True
                        
                        if not is_safe:
                            findings.append(Finding(
                                rule_id="OWASP-A08-DESER",
                                analyzer="OwaspScanner",
                                severity=Severity.ERROR,
                                message="Insecure Deserialization: Usage of dangerous deserialization functions like pickle or unsafe yaml.load.",
                                file_path=rel_path,
                                line_number=node.start_point[0] + 1,
                                snippet=get_line_snippet(node.start_point[0])
                            ))

            for child in node.children:
                traverse(child)

        traverse(tree.root_node)
        return findings
