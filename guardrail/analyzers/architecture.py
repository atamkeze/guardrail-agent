"""Tree-sitter based architectural layer boundary and import analyzer.

Enforces clean architectural boundaries (e.g. Clean Architecture, DDD, Hexagonal)
to prevent AI coding agents from importing forbidden layers (e.g., domain importing infrastructure).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter
import tree_sitter_python

from guardrail.config import ArchitectureConfig
from guardrail.git_diff import DiffResult
from guardrail.models import Finding, Severity


@dataclass
class ImportInfo:
    module: str
    line_number: int  # 1-indexed
    column: int
    snippet: str
    is_relative: bool = False
    relative_level: int = 0


class ArchitectureAnalyzer:
    """Analyzes Python source files for architectural layer violations using tree-sitter."""

    def __init__(self, config: ArchitectureConfig):
        self.config = config
        self._language = tree_sitter.Language(tree_sitter_python.language())
        self._parser = tree_sitter.Parser(self._language)

    def determine_layer(self, file_path: str) -> Optional[str]:
        """Determine which architectural layer a given file belongs to."""
        normalized = file_path.replace("\\", "/").strip("/")
        parts = normalized.split("/")

        for layer_name, patterns in self.config.layers.items():
            for pattern in patterns:
                clean_pat = pattern.replace("\\", "/").strip("/")
                # Direct glob match
                if fnmatch.fnmatch(normalized, clean_pat):
                    return layer_name
                # Partial directory match e.g. "domain" in parts
                if clean_pat.strip("*").strip("/") in parts:
                    return layer_name
        return None

    def parse_imports(self, code_bytes: bytes) -> List[ImportInfo]:
        """Parse source code with tree-sitter to find all import statements."""
        tree = self._parser.parse(code_bytes)
        imports: List[ImportInfo] = []
        code_lines = code_bytes.decode("utf-8", errors="replace").splitlines()

        def get_line_snippet(line_idx: int) -> str:
            if 0 <= line_idx < len(code_lines):
                return code_lines[line_idx].strip()
            return ""

        def traverse(node: tree_sitter.Node) -> None:
            if node.type == "import_statement":
                # e.g. import os, sys, app.domain.user as u
                for child in node.children:
                    if child.type == "dotted_name":
                        mod = child.text.decode("utf-8")
                        imports.append(
                            ImportInfo(
                                module=mod,
                                line_number=node.start_point[0] + 1,
                                column=node.start_point[1],
                                snippet=get_line_snippet(node.start_point[0]),
                            )
                        )
                    elif child.type == "aliased_import":
                        for subchild in child.children:
                            if subchild.type == "dotted_name":
                                mod = subchild.text.decode("utf-8")
                                imports.append(
                                    ImportInfo(
                                        module=mod,
                                        line_number=node.start_point[0] + 1,
                                        column=node.start_point[1],
                                        snippet=get_line_snippet(node.start_point[0]),
                                    )
                                )
                                break

            elif node.type == "import_from_statement":
                # e.g. from app.infrastructure.database import db
                # or: from ..infrastructure import db
                module_name = ""
                is_rel = False
                rel_level = 0

                for child in node.children:
                    if child.type == "dotted_name":
                        module_name = child.text.decode("utf-8")
                        break
                    elif child.type == "relative_import":
                        is_rel = True
                        rel_text = child.text.decode("utf-8")
                        # count leading dots
                        rel_level = len(rel_text) - len(rel_text.lstrip("."))
                        mod_part = rel_text.lstrip(".")
                        module_name = mod_part
                        break

                if module_name or is_rel:
                    imports.append(
                        ImportInfo(
                            module=module_name,
                            line_number=node.start_point[0] + 1,
                            column=node.start_point[1],
                            snippet=get_line_snippet(node.start_point[0]),
                            is_relative=is_rel,
                            relative_level=rel_level,
                        )
                    )

            for child in node.children:
                traverse(child)

        traverse(tree.root_node)
        return imports

    def resolve_import_layer(self, imp: ImportInfo, source_file_path: str) -> Optional[str]:
        """Resolve which layer an imported module targets."""
        target_path_str = imp.module.replace(".", "/")

        if imp.is_relative:
            # Resolve relative to source file
            source_dir = Path(source_file_path).parent
            # Move up (level - 1) directories for leading dots
            target_dir = source_dir
            for _ in range(max(0, imp.relative_level - 1)):
                target_dir = target_dir.parent
            if imp.module:
                target_path = target_dir / imp.module.replace(".", "/")
            else:
                target_path = target_dir
            target_path_str = str(target_path).replace("\\", "/")

        return self.determine_layer(target_path_str)

    def analyze_file(
        self,
        file_path: str,
        code_bytes: bytes,
        diff_result: Optional[DiffResult] = None,
    ) -> List[Finding]:
        """Analyze a single Python file for architectural layer boundary drift."""
        if not self.config.enabled:
            return []

        source_layer = self.determine_layer(file_path)
        if not source_layer:
            # File is not assigned to an architectural layer
            return []

        # Find rules applying to this source layer
        active_rules = [
            r for r in self.config.forbidden_imports if r.source_layer == source_layer
        ]
        if not active_rules:
            return []

        imports = self.parse_imports(code_bytes)
        findings: List[Finding] = []

        for imp in imports:
            # If diff_result is provided, verify this line was modified/added
            if diff_result is not None:
                if not diff_result.is_line_added(file_path, imp.line_number):
                    continue

            target_layer = self.resolve_import_layer(imp, file_path)

            for rule in active_rules:
                # Disallowed layer check
                if target_layer and target_layer in rule.disallowed_layers:
                    findings.append(
                        Finding(
                            rule_id="GUARD-ARCH-001",
                            analyzer="architecture",
                            severity=Severity.ERROR,
                            message=(
                                f"Architectural drift: Layer '{source_layer}' is forbidden from importing "
                                f"layer '{target_layer}' ('{imp.module}'). {rule.reason}"
                            ),
                            file_path=file_path,
                            line_number=imp.line_number,
                            column=imp.column,
                            snippet=imp.snippet,
                            details={
                                "source_layer": source_layer,
                                "target_layer": target_layer,
                                "imported_module": imp.module,
                                "reason": rule.reason,
                            },
                        )
                    )

                # Disallowed specific module check
                for dis_mod in rule.disallowed_modules:
                    if imp.module == dis_mod or imp.module.startswith(f"{dis_mod}."):
                        findings.append(
                            Finding(
                                rule_id="GUARD-ARCH-002",
                                analyzer="architecture",
                                severity=Severity.ERROR,
                                message=(
                                    f"Architectural drift: Layer '{source_layer}' is forbidden from importing "
                                    f"module '{dis_mod}'. {rule.reason}"
                                ),
                                file_path=file_path,
                                line_number=imp.line_number,
                                column=imp.column,
                                snippet=imp.snippet,
                                details={
                                    "source_layer": source_layer,
                                    "disallowed_module": dis_mod,
                                    "reason": rule.reason,
                                },
                            )
                        )

        return findings
