"""Tests for security lens."""

import pytest

from parallax.core.config import LensConfig
from parallax.core.types import Severity
from parallax.diff.types import DiffHunk, DiffLine, DiffLineKind, FileDiff, ParsedDiff
from parallax.lang.python import PythonAnalyzer
from parallax.lenses.base import AnalysisContext, LensRegistry
from parallax.lenses.security import SecurityLens


def create_context(source: str, changed_lines: list[int] | None = None) -> AnalysisContext:
    """Create a test context with the given source and changed lines.
    
    If changed_lines is None, all lines are considered changed.
    """
    # Don't strip - preserve line numbers
    source_lines = source.split("\n")
    
    # Default: all lines changed
    if changed_lines is None:
        changed_lines = list(range(1, len(source_lines) + 1))
    
    # Create diff with specified lines changed
    lines = []
    for i, content in enumerate(source_lines):
        line_num = i + 1
        if line_num in changed_lines:
            lines.append(
                DiffLine(kind=DiffLineKind.ADD, content=content, old_line=None, new_line=line_num)
            )
        else:
            lines.append(
                DiffLine(kind=DiffLineKind.CONTEXT, content=content, old_line=line_num, new_line=line_num)
            )

    hunk = DiffHunk(
        old_start=1,
        old_count=len(source_lines),
        new_start=1,
        new_count=len(source_lines),
        lines=tuple(lines),
        header="@@",
    )
    file_diff = FileDiff(old_path="test.py", new_path="test.py", hunks=(hunk,))
    diff = ParsedDiff(files=(file_diff,))

    # Parse source
    analyzer = PythonAnalyzer()
    ast = analyzer.parse_source(source, path="test.py")

    return AnalysisContext(diff=diff, files={"test.py": ast}, config=LensConfig())


class TestSecurityLensRegistration:
    """Tests for security lens registration."""

    def test_lens_registered(self):
        """Test that security lens can be instantiated and has correct name."""
        # Test via direct instantiation (registry may be cleared by other tests)
        lens = SecurityLens()
        assert lens.name == "security"

    def test_lens_in_registry_after_import(self):
        """Test that importing the lens registers it."""
        # Clear and re-register
        LensRegistry.clear()
        # Re-import to trigger registration
        import importlib
        import parallax.lenses.security
        importlib.reload(parallax.lenses.security)
        
        lens_class = LensRegistry.get("security")
        assert lens_class is not None

    def test_lens_properties(self):
        """Test lens name and description."""
        lens = SecurityLens()
        assert lens.name == "security"
        assert "security" in lens.description.lower()


class TestSQLInjection:
    """Tests for SQL injection detection."""

    def test_detect_fstring_sql(self):
        """Test detecting f-string in SQL query."""
        source = 'user_id = request.args.get("id")\ncursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        context = create_context(source)  # All lines changed
        lens = SecurityLens()
        annotations = lens.analyze(context)

        sql_annotations = [a for a in annotations if a.rule == "sql_injection"]
        assert len(sql_annotations) == 1
        assert sql_annotations[0].severity == Severity.HIGH
        assert sql_annotations[0].confidence == 0.9

    def test_detect_concat_sql(self):
        """Test detecting string concatenation in SQL query."""
        source = 'user_id = request.args.get("id")\ncursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        sql_annotations = [a for a in annotations if a.rule == "sql_injection"]
        assert len(sql_annotations) == 1
        assert sql_annotations[0].severity == Severity.HIGH

    def test_detect_percent_format_sql(self):
        """Test detecting % formatting in SQL query."""
        source = 'user_id = request.args.get("id")\ncursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        sql_annotations = [a for a in annotations if a.rule == "sql_injection"]
        assert len(sql_annotations) == 1

    def test_no_flag_parameterized_query(self):
        """Test that parameterized queries are not flagged."""
        source = 'user_id = request.args.get("id")\ncursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        sql_annotations = [a for a in annotations if a.rule == "sql_injection"]
        assert len(sql_annotations) == 0

    def test_no_flag_unchanged_lines(self):
        """Test that unchanged lines are not flagged."""
        source = 'user_id = request.args.get("id")\ncursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        # Only line 1 changed, not line 2 with the SQL
        context = create_context(source, [1])
        lens = SecurityLens()
        annotations = lens.analyze(context)

        sql_annotations = [a for a in annotations if a.rule == "sql_injection"]
        assert len(sql_annotations) == 0


class TestHardcodedSecrets:
    """Tests for hardcoded secrets detection."""

    def test_detect_hardcoded_password(self):
        """Test detecting hardcoded password."""
        source = 'password = "super_secret_123"'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        secret_annotations = [a for a in annotations if a.rule == "hardcoded_secrets"]
        assert len(secret_annotations) == 1
        assert secret_annotations[0].severity == Severity.HIGH

    def test_detect_hardcoded_api_key(self):
        """Test detecting hardcoded API key."""
        source = 'API_KEY = "sk-1234567890abcdef"'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        secret_annotations = [a for a in annotations if a.rule == "hardcoded_secrets"]
        assert len(secret_annotations) == 1

    def test_detect_hardcoded_token(self):
        """Test detecting hardcoded token."""
        source = 'auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        secret_annotations = [a for a in annotations if a.rule == "hardcoded_secrets"]
        assert len(secret_annotations) == 1

    def test_no_flag_env_variable(self):
        """Test that environment variable lookups are not flagged."""
        source = 'import os\npassword = os.environ.get("PASSWORD")'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        secret_annotations = [a for a in annotations if a.rule == "hardcoded_secrets"]
        assert len(secret_annotations) == 0

    def test_no_flag_placeholder(self):
        """Test that placeholder values are not flagged."""
        source = 'password = "placeholder"'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        secret_annotations = [a for a in annotations if a.rule == "hardcoded_secrets"]
        assert len(secret_annotations) == 0

    def test_no_flag_empty_string(self):
        """Test that empty strings are not flagged."""
        source = 'password = ""'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        secret_annotations = [a for a in annotations if a.rule == "hardcoded_secrets"]
        assert len(secret_annotations) == 0

    def test_no_flag_non_secret_variable(self):
        """Test that normal variables are not flagged."""
        source = 'username = "john_doe"'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        secret_annotations = [a for a in annotations if a.rule == "hardcoded_secrets"]
        assert len(secret_annotations) == 0


class TestCommandInjection:
    """Tests for command injection detection."""

    def test_detect_os_system_fstring(self):
        """Test detecting os.system with f-string."""
        source = 'import os\nuser_input = input()\nos.system(f"ls {user_input}")'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        cmd_annotations = [a for a in annotations if a.rule == "command_injection"]
        assert len(cmd_annotations) == 1
        assert cmd_annotations[0].severity == Severity.CRITICAL

    def test_detect_subprocess_shell_true(self):
        """Test detecting subprocess with shell=True and variable."""
        source = 'import subprocess\ncmd = user_input\nsubprocess.run(cmd, shell=True)'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        cmd_annotations = [a for a in annotations if a.rule == "command_injection"]
        assert len(cmd_annotations) == 1
        assert cmd_annotations[0].severity == Severity.CRITICAL

    def test_no_flag_subprocess_list_args(self):
        """Test that subprocess with list args is not flagged."""
        source = 'import subprocess\nsubprocess.run(["ls", "-la"])'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        cmd_annotations = [a for a in annotations if a.rule == "command_injection"]
        assert len(cmd_annotations) == 0

    def test_no_flag_os_system_literal(self):
        """Test that os.system with literal string is not flagged."""
        source = 'import os\nos.system("ls -la")'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        cmd_annotations = [a for a in annotations if a.rule == "command_injection"]
        assert len(cmd_annotations) == 0


class TestXSS:
    """Tests for XSS vulnerability detection."""

    def test_detect_markup_fstring(self):
        """Test detecting Markup() with f-string."""
        source = 'from markupsafe import Markup\nuser_input = request.args.get("name")\nhtml = Markup(f"<h1>Hello {user_input}</h1>")'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        xss_annotations = [a for a in annotations if a.rule == "xss"]
        assert len(xss_annotations) == 1
        assert xss_annotations[0].severity == Severity.HIGH

    def test_detect_mark_safe_variable(self):
        """Test detecting mark_safe() with variable."""
        source = 'from django.utils.safestring import mark_safe\nhtml = mark_safe(user_content)'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        xss_annotations = [a for a in annotations if a.rule == "xss"]
        assert len(xss_annotations) == 1
        assert xss_annotations[0].severity == Severity.MEDIUM

    def test_no_flag_markup_literal(self):
        """Test that Markup with literal string is not flagged."""
        source = 'from markupsafe import Markup\nhtml = Markup("<h1>Static Content</h1>")'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        xss_annotations = [a for a in annotations if a.rule == "xss"]
        assert len(xss_annotations) == 0


class TestPathTraversal:
    """Tests for path traversal detection."""

    def test_detect_open_fstring(self):
        """Test detecting open() with f-string path."""
        source = 'filename = request.args.get("file")\nwith open(f"/data/{filename}") as f:\n    content = f.read()'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        path_annotations = [a for a in annotations if a.rule == "path_traversal"]
        assert len(path_annotations) == 1
        assert path_annotations[0].severity == Severity.HIGH

    def test_detect_open_concat(self):
        """Test detecting open() with concatenated path."""
        source = 'filename = request.args.get("file")\nf = open("/data/" + filename, "r")'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        path_annotations = [a for a in annotations if a.rule == "path_traversal"]
        assert len(path_annotations) == 1

    def test_no_flag_literal_path(self):
        """Test that literal paths are not flagged."""
        source = 'with open("/etc/config.yaml") as f:\n    config = f.read()'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        path_annotations = [a for a in annotations if a.rule == "path_traversal"]
        assert len(path_annotations) == 0


class TestWeakCrypto:
    """Tests for weak cryptography detection."""

    def test_detect_md5(self):
        """Test detecting MD5 usage."""
        source = 'import hashlib\nhash = hashlib.md5(password.encode())'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        crypto_annotations = [a for a in annotations if a.rule == "weak_crypto"]
        assert len(crypto_annotations) == 1
        assert "MD5" in crypto_annotations[0].message

    def test_detect_sha1(self):
        """Test detecting SHA1 usage."""
        source = 'import hashlib\nhash = hashlib.sha1(data.encode())'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        crypto_annotations = [a for a in annotations if a.rule == "weak_crypto"]
        assert len(crypto_annotations) == 1
        assert "SHA1" in crypto_annotations[0].message

    def test_detect_hashlib_new_md5(self):
        """Test detecting hashlib.new('md5')."""
        source = 'import hashlib\nhash = hashlib.new("md5", data)'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        crypto_annotations = [a for a in annotations if a.rule == "weak_crypto"]
        assert len(crypto_annotations) == 1

    def test_detect_des_import(self):
        """Test detecting DES import."""
        source = 'from Crypto.Cipher import DES'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        crypto_annotations = [a for a in annotations if a.rule == "weak_crypto"]
        assert len(crypto_annotations) == 1
        assert "DES" in crypto_annotations[0].message

    def test_no_flag_sha256(self):
        """Test that SHA-256 is not flagged."""
        source = 'import hashlib\nhash = hashlib.sha256(data.encode())'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        crypto_annotations = [a for a in annotations if a.rule == "weak_crypto"]
        assert len(crypto_annotations) == 0


class TestAnnotationDetails:
    """Tests for annotation details."""

    def test_annotation_has_suggestion(self):
        """Test that annotations include suggestions."""
        source = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        assert len(annotations) == 1
        assert annotations[0].suggestion is not None
        assert len(annotations[0].suggestion) > 0

    def test_annotation_has_category(self):
        """Test that annotations include category."""
        source = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        context = create_context(source)
        lens = SecurityLens()
        annotations = lens.analyze(context)

        assert len(annotations) == 1
        assert annotations[0].category == "injection"

    def test_annotation_location(self):
        """Test that annotation has correct location."""
        source = 'x = 1\ncursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\ny = 2'
        context = create_context(source, [2])  # Only line 2 changed
        lens = SecurityLens()
        annotations = lens.analyze(context)

        assert len(annotations) == 1
        assert annotations[0].location.file == "test.py"
        assert annotations[0].location.start_line == 2
