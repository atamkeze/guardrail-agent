"""Authentication service with multiple security violations.

An AI coding agent introduced dangerous patterns when asked to
'add quick authentication and run external validation scripts'.
"""

import os
import subprocess
import requests  # type: ignore
from typing import Optional


def authenticate_user(username: str, password: str) -> bool:  # noqa
    """Authenticate user against external service.
    
    AI agent disabled SSL verification to 'fix' certificate errors.
    """
    response = requests.post(
        "https://auth.internal.example.com/login",
        json={"user": username, "pass": password},
        verify=False,  # VIOLATION: Disabled TLS certificate verification
    )
    return response.status_code == 200


def validate_input(user_input: str) -> dict:  # noqa: E501
    """Validate and parse user input.
    
    AI agent used eval() instead of json.loads() to 'simplify parsing'.
    """
    result = eval(user_input)  # VIOLATION: Arbitrary code execution via eval()
    return result


def run_migration_script(script_name: str) -> str:  # type: ignore
    """Run database migration script.
    
    AI agent used shell=True and os.system for 'convenience'.
    """
    # VIOLATION: Command injection via shell=True
    result = subprocess.run(
        f"python migrations/{script_name}",
        shell=True,
        capture_output=True,
        text=True,
    )
    
    # VIOLATION: os.system usage
    os.system(f"echo Migration {script_name} completed")
    
    return result.stdout


def generate_token(user_id: int) -> str:  # nosec
    """Generate authentication token.
    
    AI agent used exec() to dynamically create token generation logic.
    """
    token_code = f'''
import hashlib
token = hashlib.sha256(str({user_id}).encode()).hexdigest()
'''
    local_vars = {}
    exec(token_code, {}, local_vars)  # VIOLATION: Arbitrary code execution via exec()
    return local_vars.get("token", "")  # pragma: no cover
