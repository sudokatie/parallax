"""Integration tests for Parallax CLI."""

import subprocess
import sys
from pathlib import Path
from contextlib import contextmanager

import pytest
from click.testing import CliRunner

from parallax.cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI test runner."""
    return CliRunner()


@contextmanager
def git_repo(runner: CliRunner):
    """Context manager that creates a temporary git repo with initial commit."""
    with runner.isolated_filesystem():
        subprocess.run(["git", "init"], capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], capture_output=True)
        # Create initial commit so HEAD exists
        Path("README.md").write_text("# Test\n")
        subprocess.run(["git", "add", "."], capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], capture_output=True)
        yield


class TestCLICommands:
    """Tests for CLI commands."""

    def test_version(self, runner: CliRunner) -> None:
        """Test version command."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "parallax" in result.output.lower()

    def test_help(self, runner: CliRunner) -> None:
        """Test help output."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "analyze" in result.output
        assert "lenses" in result.output
        assert "init" in result.output

    def test_lenses_command(self, runner: CliRunner) -> None:
        """Test lenses listing command."""
        result = runner.invoke(cli, ["lenses"])
        assert result.exit_code == 0
        assert "security" in result.output
        assert "maintainability" in result.output
        assert "testing" in result.output

    def test_init_command(self, runner: CliRunner) -> None:
        """Test init command creates config file."""
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["init"])
            assert result.exit_code == 0
            assert Path(".parallax.yaml").exists()

            # Read and verify config content
            content = Path(".parallax.yaml").read_text()
            assert "lenses:" in content
            assert "security:" in content

    def test_init_no_overwrite(self, runner: CliRunner) -> None:
        """Test init doesn't overwrite existing config."""
        with runner.isolated_filesystem():
            # Create existing config
            Path(".parallax.yaml").write_text("existing: true")

            result = runner.invoke(cli, ["init"])
            assert result.exit_code == 1
            assert "already exists" in result.output

    def test_init_force_overwrite(self, runner: CliRunner) -> None:
        """Test init --force overwrites existing config."""
        with runner.isolated_filesystem():
            # Create existing config
            Path(".parallax.yaml").write_text("existing: true")

            result = runner.invoke(cli, ["init", "--force"])
            assert result.exit_code == 0

            # Verify overwritten
            content = Path(".parallax.yaml").read_text()
            assert "existing" not in content


class TestAnalyzeCommand:
    """Tests for analyze command."""

    def test_analyze_requires_target(self, runner: CliRunner) -> None:
        """Test analyze fails without target."""
        result = runner.invoke(cli, ["analyze"])
        assert result.exit_code == 2
        assert "Must provide TARGET" in result.output or "Error" in result.output

    def test_analyze_nonexistent_target(self, runner: CliRunner) -> None:
        """Test analyze fails with nonexistent target."""
        result = runner.invoke(cli, ["analyze", "/nonexistent/path"])
        # Should fail with exit code 2 or 3
        assert result.exit_code in (2, 3)

    def test_analyze_empty_directory(self, runner: CliRunner) -> None:
        """Test analyze on directory with no changes."""
        with git_repo(runner):
            result = runner.invoke(cli, ["analyze", "."])
            # Should succeed with no findings (no uncommitted changes)
            assert result.exit_code == 0

    def test_analyze_output_formats(self, runner: CliRunner) -> None:
        """Test analyze accepts all output format options."""
        with git_repo(runner):
            for fmt in ["text", "json", "sarif", "markdown"]:
                result = runner.invoke(cli, ["analyze", ".", "-o", fmt])
                assert result.exit_code == 0, f"Failed for format {fmt}"


class TestCLIOptions:
    """Tests for CLI options."""

    def test_verbose_flag(self, runner: CliRunner) -> None:
        """Test verbose flag is accepted."""
        with git_repo(runner):
            result = runner.invoke(cli, ["analyze", ".", "-v"])
            assert result.exit_code == 0

    def test_quiet_flag(self, runner: CliRunner) -> None:
        """Test quiet flag is accepted."""
        with git_repo(runner):
            result = runner.invoke(cli, ["analyze", ".", "-q"])
            assert result.exit_code == 0

    def test_lens_filter(self, runner: CliRunner) -> None:
        """Test lens filter option."""
        with git_repo(runner):
            result = runner.invoke(cli, ["analyze", ".", "-l", "security"])
            assert result.exit_code == 0

    def test_min_severity(self, runner: CliRunner) -> None:
        """Test min-severity option."""
        with git_repo(runner):
            result = runner.invoke(cli, ["analyze", ".", "--min-severity", "high"])
            assert result.exit_code == 0

    def test_min_confidence(self, runner: CliRunner) -> None:
        """Test min-confidence option."""
        with git_repo(runner):
            result = runner.invoke(cli, ["analyze", ".", "--min-confidence", "0.8"])
            assert result.exit_code == 0


class TestExitCodes:
    """Tests for exit codes."""

    def test_success_exit_code(self, runner: CliRunner) -> None:
        """Test exit code 0 for successful analysis."""
        with git_repo(runner):
            result = runner.invoke(cli, ["analyze", "."])
            assert result.exit_code == 0

    def test_config_error_exit_code(self, runner: CliRunner) -> None:
        """Test exit code 2 for config errors."""
        with git_repo(runner):
            # Create invalid config
            Path(".parallax.yaml").write_text("invalid: [yaml: syntax")

            result = runner.invoke(cli, ["analyze", "."])
            assert result.exit_code in (2, 3)
