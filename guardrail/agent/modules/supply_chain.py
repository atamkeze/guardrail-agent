"""Agent Module A: Supply Chain & Dependency Vulnerability Scanner using OSV.dev API and PyPI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx

from guardrail.analyzers.slopsquatting import check_dependencies_async
from guardrail.config import SlopsquattingConfig
from guardrail.git_diff import DependencyChange
from guardrail.models import Finding, Severity


class SupplyChainScanner:
    """Audits multi-ecosystem dependencies against OSV.dev vulnerability database and PyPI registry."""

    def __init__(self, osv_api_url: str = "https://api.osv.dev/v1/query"):
        self.osv_api_url = osv_api_url

    async def scan_dependencies(self, root: Path) -> List[Finding]:
        findings: List[Finding] = []
        py_deps: List[DependencyChange] = []
        other_deps: List[Dict[str, str]] = []  # name, ecosystem, file, version

        # 1. Parse manifest files
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            fname = p.name.lower()
            rel_path = str(p.relative_to(root)).replace("\\", "/")

            if ".git" in rel_path or ".venv" in rel_path or "node_modules" in rel_path:
                continue

            # Python
            if fname == "requirements.txt" or (fname.startswith("requirements") and fname.endswith(".txt")):
                try:
                    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    for idx, line in enumerate(lines, 1):
                        cleaned = line.strip().split("#")[0].strip()
                        if not cleaned or cleaned.startswith("-"):
                            continue
                        parts = cleaned.replace("==", " ").replace(">=", " ").replace("<=", " ").split()
                        pkg = parts[0]
                        ver = parts[1] if len(parts) > 1 else None
                        py_deps.append(DependencyChange(package_name=pkg, specifier=ver or "", source_file=rel_path, line_number=idx))
                        other_deps.append({"name": pkg, "ecosystem": "PyPI", "file": rel_path, "version": ver or "0.0.0", "line": idx})
                except Exception:
                    pass

            # NPM
            elif fname == "package.json":
                try:
                    data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    for pkg, ver in deps.items():
                        clean_ver = ver.lstrip("^~>=<")
                        other_deps.append({"name": pkg, "ecosystem": "npm", "file": rel_path, "version": clean_ver or "1.0.0", "line": 1})
                except Exception:
                    pass

            # Composer / PHP
            elif fname == "composer.json":
                try:
                    data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                    deps = {**data.get("require", {}), **data.get("require-dev", {})}
                    for pkg, ver in deps.items():
                        if pkg != "php" and not pkg.startswith("ext-"):
                            clean_ver = str(ver).lstrip("^~>=<")
                            other_deps.append({"name": pkg, "ecosystem": "Packagist", "file": rel_path, "version": clean_ver or "1.0.0", "line": 1})
                except Exception:
                    pass

        # 2. Run Slopsquatting on Python dependencies
        if py_deps:
            try:
                slop_findings = await check_dependencies_async(py_deps, SlopsquattingConfig())
                findings.extend(slop_findings)
            except Exception:
                pass

        # 3. Query OSV.dev for CVEs
        if other_deps:
            osv_findings = await self._check_osv_batch(other_deps[:25])
            findings.extend(osv_findings)

        return findings

    async def _check_osv_batch(self, deps: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)

        async with httpx.AsyncClient(timeout=8.0, limits=limits) as client:
            tasks = [self._query_osv_single(client, d) for d in deps]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    findings.extend(r)
        return findings

    async def _query_osv_single(self, client: httpx.AsyncClient, dep: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        payload = {
            "package": {
                "name": dep["name"],
                "ecosystem": dep["ecosystem"]
            }
        }
        if dep.get("version"):
            payload["version"] = dep["version"]

        try:
            resp = await client.post(self.osv_api_url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulns", [])
                for v in vulns[:3]:
                    vid = v.get("id", "UNKNOWN-CVE")
                    summary = v.get("summary") or v.get("details", "")[:120]
                    aliases = ", ".join(v.get("aliases", []))
                    msg = f"Known Vulnerability [{vid}] in {dep['ecosystem']} package '{dep['name']}'"
                    if aliases:
                        msg += f" ({aliases})"
                    msg += f": {summary}"

                    findings.append(Finding(
                        rule_id=f"CVE-{vid}",
                        analyzer="SupplyChainScanner",
                        severity=Severity.ERROR,
                        message=msg,
                        file_path=dep["file"],
                        line_number=dep.get("line", 1),
                        snippet=f"{dep['name']}=={dep.get('version', '')}"
                    ))
        except Exception:
            pass

        return findings
