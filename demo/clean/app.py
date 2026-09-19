"""Clean application module with no violations.

This file demonstrates code that passes all GuardRail-Agent checks:
- No hallucinated dependencies
- No architectural boundary violations  
- No linter suppressions or dangerous calls
"""

import json
import logging
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AppConfig:
    """Application configuration container."""
    app_name: str
    debug: bool = False
    log_level: str = "INFO"
    max_connections: int = 100


def load_config(config_path: str) -> AppConfig:
    """Load application configuration from a JSON file."""
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    return AppConfig(
        app_name=data.get("app_name", "MyApp"),
        debug=data.get("debug", False),
        log_level=data.get("log_level", "INFO"),
        max_connections=data.get("max_connections", 100),
    )


def format_user_list(users: List[dict]) -> str:
    """Format a list of users as a readable string."""
    lines = []
    for user in users:
        name = user.get("name", "Unknown")
        email = user.get("email", "N/A")
        lines.append(f"  - {name} ({email})")
    return "\n".join(lines)


def calculate_checksum(data: str) -> str:
    """Calculate a simple checksum for data integrity verification."""
    import hashlib
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
