"""Agent module for Secrets and Credential Leakage Scanning."""

import math
import re
from pathlib import Path
from typing import List

from guardrail.cli import collect_project_files
from guardrail.models import Finding, Severity

# Known secret patterns
SECRET_PATTERNS = {
    "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "Stripe Secret Key": r"(?:sk_live_|rk_live_)[a-zA-Z0-9]{24,99}",
    "GitHub Token": r"(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Generic Password/Secret Assignment": r"(?i)(?:password|secret|token|api_key|access_key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
}

def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

class SecretsScanner:
    def __init__(self, exclude_patterns: List[str] = None):
        self.exclude_patterns = exclude_patterns or [
            ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"
        ]
        self.compiled_patterns = {name: re.compile(pat) for name, pat in SECRET_PATTERNS.items()}

    def scan_directory(self, root: Path) -> List[Finding]:
        findings: List[Finding] = []
        files = collect_project_files(root, self.exclude_patterns)
        
        for file_path in files:
            # Check for committed .env files
            filename = file_path.name.lower()
            if filename == ".env" or filename.startswith(".env."):
                if filename != ".env.example":
                    rel_path = str(file_path.relative_to(root)).replace("\\", "/")
                    findings.append(Finding(
                        rule_id="SEC-001",
                        analyzer="SecretsScanner",
                        severity=Severity.ERROR,
                        message="Environment file (.env) committed to repository.",
                        file_path=rel_path,
                        line_number=1,
                        snippet=filename
                    ))
            
            # Read file content for secrets
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(root)).replace("\\", "/")
                
                for line_idx, line in enumerate(content.splitlines()):
                    # 1. Regex Match
                    for name, pat in self.compiled_patterns.items():
                        match = pat.search(line)
                        if match:
                            snippet = line.strip()[:100]  # truncate to avoid dumping huge lines
                            findings.append(Finding(
                                rule_id="SEC-002",
                                analyzer="SecretsScanner",
                                severity=Severity.ERROR,
                                message=f"Detected potential {name}.",
                                file_path=rel_path,
                                line_number=line_idx + 1,
                                snippet=snippet
                            ))
                            
                    # 2. Entropy Check on long alphanumeric strings that might be secrets
                    # Extract words that are long enough and look like base64 or hex
                    words = re.findall(r"\b[A-Za-z0-9/+=]{20,}\b", line)
                    for word in words:
                        # Skip things that are obviously just long words or camelCase variables
                        if word.isalpha() and word.islower():
                            continue
                        
                        ent = shannon_entropy(word)
                        if ent > 4.8:
                            # Verify it's not already matched by regex to avoid duplicates
                            is_duplicate = any(p.search(word) for p in self.compiled_patterns.values())
                            if not is_duplicate:
                                findings.append(Finding(
                                    rule_id="SEC-003",
                                    analyzer="SecretsScanner",
                                    severity=Severity.WARNING,
                                    message=f"High entropy string detected (entropy: {ent:.2f}), possible secret/token.",
                                    file_path=rel_path,
                                    line_number=line_idx + 1,
                                    snippet=line.strip()[:100]
                                ))
            except Exception:
                # Skip unreadable or binary files that slip through
                continue

        return findings
