"""Tests for the analysis engine."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from parallax.core.config import Config, LensConfig
from parallax.core.engine import AnalysisEngine, EngineError
from parallax.core.types import Annotation, AnalysisResult, Location, Severity
from parallax.diff.types import DiffHunk, DiffLine, DiffLineKind, FileDiff, ParsedDiff


@pytest.fixture
def basic_config():
    """Create a basic config for testing."""
    return Config(
        lenses={
            "security": LensConfig(enabled=True),
            "maintainability": LensConfig(enabled=True),
            "testing": LensConfig(enabled=True),
        },
        min_confidence=0.5,
        output_format="text",
    )


@pytest.fixture
def temp_git_repo(tmp_path):
    """Create a temporary git repository."""
    import subprocess
    
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    
    # Initialize git repo
    subprocess.run(["git", "init"], cwd=repo_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    
    # Create initial commit
    (repo_path / "README.md").write_text("# Test\n")
    subprocess.run(["git", "add", "."], cwd=repo_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    
    return repo_path


class TestAnalysisEngine:
    """Tests for AnalysisEngine."""

    def test_init(self, basic_config):
        """Test engine initialization."""
        engine = AnalysisEngine(basic_config)
        assert engine.config == basic_config
        assert engine.verbose is False
        assert engine.quiet is False

    def test_init_with_options(self, basic_config):
        """Test engine initialization with verbose/quiet."""
        engine = AnalysisEngine(basic_config, verbose=True, quiet=True)
        assert engine.verbose is True
        assert engine.quiet is True

    def test_analyze_nonexistent_target(self, basic_config):
        """Test analyzing a target that doesn't exist."""
        engine = AnalysisEngine(basic_config)
        with pytest.raises(EngineError, match="Target not found"):
            engine.analyze("/nonexistent/path")

    def test_analyze_empty_diff_file(self, basic_config, tmp_path):
        """Test analyzing an empty diff file."""
        diff_file = tmp_path / "empty.patch"
        diff_file.write_text("")
        
        engine = AnalysisEngine(basic_config)
        result = engine.analyze(str(diff_file))
        
        assert isinstance(result, AnalysisResult)
        assert result.annotations == []

    def test_analyze_simple_diff_file(self, basic_config, tmp_path):
        """Test analyzing a simple diff file."""
        # Create a Python file to analyze
        py_file = tmp_path / "test.py"
        py_file.write_text("password = 'secret123'\n")
        
        # Create a diff file
        diff_content = """diff --git a/test.py b/test.py
new file mode 100644
--- /dev/null
+++ b/test.py
@@ -0,0 +1 @@
+password = 'secret123'
"""
        diff_file = tmp_path / "test.patch"
        diff_file.write_text(diff_content)
        
        engine = AnalysisEngine(basic_config)
        result = engine.analyze(str(diff_file))
        
        assert isinstance(result, AnalysisResult)
        # Should find hardcoded secret
        assert any(a.rule == "hardcoded_secrets" for a in result.annotations)

    def test_analyze_git_directory_no_changes(self, basic_config, temp_git_repo):
        """Test analyzing a git directory with no uncommitted changes."""
        engine = AnalysisEngine(basic_config, quiet=True)
        result = engine.analyze(str(temp_git_repo))
        
        assert isinstance(result, AnalysisResult)
        assert result.annotations == []

    def test_analyze_git_directory_with_changes(self, basic_config, temp_git_repo):
        """Test analyzing a git directory with uncommitted changes."""
        # Create a Python file with an issue
        py_file = temp_git_repo / "bad.py"
        py_file.write_text("api_key = 'abc123xyz'\n")
        
        engine = AnalysisEngine(basic_config, quiet=True)
        result = engine.analyze(str(temp_git_repo))
        
        assert isinstance(result, AnalysisResult)


class TestEngineIgnoreRules:
    """Tests for ignore rules in the engine."""

    def test_apply_ignore_paths(self):
        """Test that ignore paths filter annotations."""
        config = Config(
            lenses={
                "security": LensConfig(enabled=True),
            },
            min_confidence=0.5,
            output_format="text",
            ignore_paths=["test_*.py", "**/test_*.py"],
        )
        engine = AnalysisEngine(config)
        
        annotations = [
            Annotation(
                lens="security",
                rule="hardcoded_secrets",
                location=Location(file="test_file.py", start_line=1, end_line=1),
                severity=Severity.HIGH,
                confidence=0.9,
                message="Test",
            ),
            Annotation(
                lens="security",
                rule="hardcoded_secrets",
                location=Location(file="main.py", start_line=1, end_line=1),
                severity=Severity.HIGH,
                confidence=0.9,
                message="Test",
            ),
        ]
        
        filtered = engine._apply_ignore_rules(annotations)
        
        assert len(filtered) == 1
        assert filtered[0].location.file == "main.py"

    def test_apply_ignore_rules_specific(self, basic_config):
        """Test that rule-specific ignores work."""
        basic_config.ignore_rules = {"security/hardcoded_secrets": ["tests/*"]}
        engine = AnalysisEngine(basic_config)
        
        annotations = [
            Annotation(
                lens="security",
                rule="hardcoded_secrets",
                location=Location(file="tests/conftest.py", start_line=1, end_line=1),
                severity=Severity.HIGH,
                confidence=0.9,
                message="Test",
            ),
            Annotation(
                lens="security",
                rule="hardcoded_secrets",
                location=Location(file="src/main.py", start_line=1, end_line=1),
                severity=Severity.HIGH,
                confidence=0.9,
                message="Test",
            ),
        ]
        
        filtered = engine._apply_ignore_rules(annotations)
        
        assert len(filtered) == 1
        assert filtered[0].location.file == "src/main.py"


class TestEngineSuppressions:
    """Tests for inline suppression handling."""

    def test_apply_suppressions_empty(self, basic_config):
        """Test applying suppressions when none exist."""
        engine = AnalysisEngine(basic_config)
        
        annotations = [
            Annotation(
                lens="security",
                rule="sql_injection",
                location=Location(file="db.py", start_line=10, end_line=10),
                severity=Severity.HIGH,
                confidence=0.9,
                message="Test",
            ),
        ]
        
        filtered = engine._apply_suppressions(annotations)
        assert filtered == annotations

    def test_apply_suppressions_filters(self, basic_config):
        """Test that suppressions filter matching annotations."""
        from parallax.core.suppression import Suppression
        
        engine = AnalysisEngine(basic_config)
        engine._suppressions = {
            "db.py": [
                Suppression(rule_pattern="security/sql_injection", line=10, is_next_line=False)
            ]
        }
        
        annotations = [
            Annotation(
                lens="security",
                rule="sql_injection",
                location=Location(file="db.py", start_line=10, end_line=10),
                severity=Severity.HIGH,
                confidence=0.9,
                message="Suppressed",
            ),
            Annotation(
                lens="security",
                rule="sql_injection",
                location=Location(file="db.py", start_line=20, end_line=20),
                severity=Severity.HIGH,
                confidence=0.9,
                message="Not suppressed",
            ),
        ]
        
        filtered = engine._apply_suppressions(annotations)
        
        assert len(filtered) == 1
        assert filtered[0].location.start_line == 20


class TestEngineGetEnabledLenses:
    """Tests for lens enablement."""

    def test_get_enabled_lenses_all(self, basic_config):
        """Test getting all enabled lenses."""
        engine = AnalysisEngine(basic_config)
        lenses = engine._get_enabled_lenses()
        
        lens_names = [lens.name for lens in lenses]
        assert "security" in lens_names
        assert "maintainability" in lens_names
        assert "testing" in lens_names

    def test_get_enabled_lenses_some_disabled(self):
        """Test getting lenses when some are disabled."""
        config = Config(
            lenses={
                "security": LensConfig(enabled=True),
                "maintainability": LensConfig(enabled=False),
                "testing": LensConfig(enabled=True),
            },
            min_confidence=0.5,
            output_format="text",
        )
        engine = AnalysisEngine(config)
        lenses = engine._get_enabled_lenses()
        
        lens_names = [lens.name for lens in lenses]
        assert "security" in lens_names
        assert "maintainability" not in lens_names
        assert "testing" in lens_names


class TestEngineCommitAnalysis:
    """Tests for commit and range analysis."""

    def test_analyze_commit(self, basic_config, temp_git_repo):
        """Test analyzing a specific commit."""
        import subprocess
        
        # Create a new commit
        py_file = temp_git_repo / "new.py"
        py_file.write_text("x = 1\n")
        subprocess.run(["git", "add", "."], cwd=temp_git_repo, capture_output=True, check=True)
        result = subprocess.run(
            ["git", "commit", "-m", "Add file"],
            cwd=temp_git_repo,
            capture_output=True,
            text=True,
            check=True,
        )
        
        # Get commit SHA
        sha_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=temp_git_repo,
            capture_output=True,
            text=True,
            check=True,
        )
        commit_sha = sha_result.stdout.strip()
        
        engine = AnalysisEngine(basic_config, quiet=True)
        result = engine.analyze_commit(commit_sha, str(temp_git_repo))
        
        assert isinstance(result, AnalysisResult)
        assert result.target == f"commit:{commit_sha}"

    def test_analyze_commit_invalid(self, basic_config, temp_git_repo):
        """Test analyzing an invalid commit."""
        engine = AnalysisEngine(basic_config)
        
        with pytest.raises(EngineError, match="Git command failed"):
            engine.analyze_commit("invalid_sha_12345", str(temp_git_repo))

    def test_analyze_range(self, basic_config, temp_git_repo):
        """Test analyzing a commit range."""
        import subprocess
        
        # Get initial commit
        initial = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=temp_git_repo,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        
        # Create a new commit
        py_file = temp_git_repo / "range.py"
        py_file.write_text("y = 2\n")
        subprocess.run(["git", "add", "."], cwd=temp_git_repo, capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "-m", "Range commit"],
            cwd=temp_git_repo,
            capture_output=True,
            check=True,
        )
        
        engine = AnalysisEngine(basic_config, quiet=True)
        result = engine.analyze_range(f"{initial}..HEAD", str(temp_git_repo))
        
        assert isinstance(result, AnalysisResult)
        assert "range:" in result.target


class TestEnginePRAnalysis:
    """Tests for PR URL parsing."""

    def test_analyze_pr_invalid_url(self, basic_config):
        """Test analyzing an invalid PR URL."""
        engine = AnalysisEngine(basic_config)
        
        with pytest.raises(EngineError, match="Unsupported PR URL format"):
            engine.analyze_pr("https://example.com/not-a-pr")

    @patch("urllib.request.urlopen")
    def test_analyze_github_pr_network_error(self, mock_urlopen, basic_config):
        """Test handling network errors for GitHub PR."""
        import urllib.error
        
        mock_urlopen.side_effect = urllib.error.URLError("Network error")
        
        engine = AnalysisEngine(basic_config)
        
        with pytest.raises(EngineError, match="Network error"):
            engine.analyze_pr("https://github.com/owner/repo/pull/123")


class TestEngineGitDiff:
    """Tests for git diff retrieval."""

    def test_get_git_diff_no_git(self, basic_config, tmp_path):
        """Test getting diff from non-git directory."""
        engine = AnalysisEngine(basic_config)
        
        with pytest.raises(EngineError):
            engine._get_git_diff(tmp_path)

    def test_get_git_diff_clean_repo(self, basic_config, temp_git_repo):
        """Test getting diff from clean repo."""
        engine = AnalysisEngine(basic_config)
        diff = engine._get_git_diff(temp_git_repo)
        
        assert isinstance(diff, ParsedDiff)
        assert diff.files == ()


class TestEngineParseSourceFiles:
    """Tests for source file parsing."""

    def test_parse_source_files_binary_skipped(self, basic_config, tmp_path):
        """Test that binary files are skipped."""
        engine = AnalysisEngine(basic_config)
        
        diff = ParsedDiff(
            files=[
                FileDiff(
                    old_path=None,
                    new_path="image.png",
                    hunks=[],
                    is_binary=True,
                )
            ]
        )
        
        files = engine._parse_source_files(diff, tmp_path)
        assert files == {}

    def test_parse_source_files_non_python_skipped(self, basic_config, tmp_path):
        """Test that non-Python files are skipped."""
        # Create a JS file
        js_file = tmp_path / "app.js"
        js_file.write_text("const x = 1;\n")
        
        engine = AnalysisEngine(basic_config)
        
        diff = ParsedDiff(
            files=(
                FileDiff(
                    old_path=None,
                    new_path="app.js",
                    hunks=(
                        DiffHunk(
                            old_start=0,
                            old_count=0,
                            new_start=1,
                            new_count=1,
                            header="@@ -0,0 +1 @@",
                            lines=(
                                DiffLine(
                                    kind=DiffLineKind.ADD,
                                    content="const x = 1;",
                                    old_line=None,
                                    new_line=1,
                                ),
                            ),
                        ),
                    ),
                    is_binary=False,
                ),
            )
        )
        
        files = engine._parse_source_files(diff, tmp_path)
        assert files == {}

    def test_parse_source_files_python_parsed(self, basic_config, tmp_path):
        """Test that Python files are parsed."""
        # Create a Python file
        py_file = tmp_path / "app.py"
        py_file.write_text("x = 1\n")
        
        engine = AnalysisEngine(basic_config)
        
        diff = ParsedDiff(
            files=(
                FileDiff(
                    old_path=None,
                    new_path="app.py",
                    hunks=(
                        DiffHunk(
                            old_start=0,
                            old_count=0,
                            new_start=1,
                            new_count=1,
                            header="@@ -0,0 +1 @@",
                            lines=(
                                DiffLine(
                                    kind=DiffLineKind.ADD,
                                    content="x = 1",
                                    old_line=None,
                                    new_line=1,
                                ),
                            ),
                        ),
                    ),
                    is_binary=False,
                ),
            )
        )
        
        files = engine._parse_source_files(diff, tmp_path)
        assert "app.py" in files

    def test_parse_source_files_with_suppressions(self, basic_config, tmp_path):
        """Test that inline suppressions are parsed."""
        # Create a Python file with suppression
        py_file = tmp_path / "suppressed.py"
        py_file.write_text("# parallax-ignore-file security/*\npassword = 'secret'\n")
        
        engine = AnalysisEngine(basic_config)
        
        diff = ParsedDiff(
            files=(
                FileDiff(
                    old_path=None,
                    new_path="suppressed.py",
                    hunks=(
                        DiffHunk(
                            old_start=0,
                            old_count=0,
                            new_start=1,
                            new_count=2,
                            header="@@ -0,0 +1,2 @@",
                            lines=(
                                DiffLine(kind=DiffLineKind.ADD, content="# parallax-ignore-file security/*", old_line=None, new_line=1),
                                DiffLine(kind=DiffLineKind.ADD, content="password = 'secret'", old_line=None, new_line=2),
                            ),
                        ),
                    ),
                    is_binary=False,
                ),
            )
        )
        
        files = engine._parse_source_files(diff, tmp_path)
        
        assert "suppressed.py" in files
        assert "suppressed.py" in engine._suppressions
        assert len(engine._suppressions["suppressed.py"]) == 1


class TestEngineLogging:
    """Tests for engine logging."""

    def test_log_quiet_mode(self, basic_config, capsys):
        """Test that logging is suppressed in quiet mode."""
        engine = AnalysisEngine(basic_config, quiet=True)
        engine._log("This should not appear")
        
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_log_normal_mode(self, basic_config, capsys):
        """Test that logging works in normal mode."""
        engine = AnalysisEngine(basic_config, quiet=False)
        engine._log("This should appear")
        
        captured = capsys.readouterr()
        assert "This should appear" in captured.out
