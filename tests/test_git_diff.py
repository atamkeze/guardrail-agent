"""Unit tests for guardrail.git_diff."""

import pytest
from guardrail.git_diff import (
    parse_unified_diff,
    extract_package_from_requirement_line,
    extract_dependencies_from_diff,
    DiffResult,
    FileDiff,
    AddedLine,
)


SAMPLE_DIFF = """diff --git a/requirements.txt b/requirements.txt
index 1234567..89abcdef 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,4 @@
 requests>=2.28.0
+fake-ai-auth-pkg>=1.0.0
 urllib3<3
+hallucinated-cache[redis]==2.1.0
diff --git a/app/domain/user.py b/app/domain/user.py
new file mode 100644
index 0000000..abcdef1
--- /dev/null
+++ b/app/domain/user.py
@@ -0,0 +1,5 @@
+from app.infrastructure.database import db_conn
+
+class User:
+    def __init__(self):
+        pass
diff --git a/app/api/views.py b/app/api/views.py
index aaaaaaa..bbbbbbb 100644
--- a/app/api/views.py
+++ b/app/api/views.py
@@ -10,0 +11,2 @@
+    # noqa: E501
+    eval("malicious_code()")
"""


def test_parse_unified_diff():
    files = parse_unified_diff(SAMPLE_DIFF)
    assert "requirements.txt" in files
    assert "app/domain/user.py" in files
    assert "app/api/views.py" in files

    req_diff = files["requirements.txt"]
    assert req_diff.status == "modified"
    assert len(req_diff.added_lines) == 2
    assert req_diff.added_lines[0].line_number == 2
    assert req_diff.added_lines[0].content == "fake-ai-auth-pkg>=1.0.0"
    assert req_diff.added_lines[1].line_number == 4
    assert req_diff.added_lines[1].content == "hallucinated-cache[redis]==2.1.0"

    user_diff = files["app/domain/user.py"]
    assert user_diff.status == "added"
    assert len(user_diff.added_lines) == 5
    assert user_diff.added_lines[0].line_number == 1
    assert "db_conn" in user_diff.added_lines[0].content

    views_diff = files["app/api/views.py"]
    assert len(views_diff.added_lines) == 2
    assert views_diff.added_lines[0].line_number == 11
    assert views_diff.added_lines[1].line_number == 12


def test_extract_package_from_requirement_line():
    assert extract_package_from_requirement_line("requests>=2.0.0") == ("requests", ">=2.0.0")
    assert extract_package_from_requirement_line("flask-login~=0.6.0 # useful comment") == ("flask-login", "~=0.6.0")
    assert extract_package_from_requirement_line("pydantic[email]==2.5.0") == ("pydantic", "==2.5.0")
    assert extract_package_from_requirement_line("some_package_name") == ("some-package-name", "")
    assert extract_package_from_requirement_line("   ") is None
    assert extract_package_from_requirement_line("# Just a comment") is None
    assert extract_package_from_requirement_line("-r other-requirements.txt") is None


def test_extract_dependencies_from_diff():
    files = parse_unified_diff(SAMPLE_DIFF)
    deps = extract_dependencies_from_diff(files)

    pkg_names = [d.package_name for d in deps]
    assert "fake-ai-auth-pkg" in pkg_names
    assert "hallucinated-cache" in pkg_names


def test_diff_result_is_line_added():
    files = parse_unified_diff(SAMPLE_DIFF)
    diff_res = DiffResult(files=files)

    assert diff_res.is_line_added("app/domain/user.py", 1) is True
    assert diff_res.is_line_added("app\\domain\\user.py", 1) is True  # Windows path normalization
    assert diff_res.is_line_added("app/domain/user.py", 999) is False
    assert diff_res.is_line_added("unknown/file.py", 1) is False
