"""Tests for inline suppression handling."""

import pytest

from parallax.core.suppression import (
    Suppression,
    SuppressionChecker,
    SuppressionParser,
    parse_file_suppressions,
)


class TestSuppressionParser:
    """Tests for SuppressionParser."""

    def test_parse_same_line_suppression(self) -> None:
        """Test parsing same-line suppression comment."""
        source = 'cursor.execute(f"SELECT * FROM {table}")  # parallax-ignore security/sql-injection'
        parser = SuppressionParser()
        suppressions = parser.parse(source)

        assert len(suppressions) == 1
        assert suppressions[0].rule_pattern == "security/sql-injection"
        assert suppressions[0].line == 1
        assert suppressions[0].is_next_line is False

    def test_parse_next_line_suppression(self) -> None:
        """Test parsing next-line suppression comment."""
        source = """# parallax-ignore-next-line maintainability/complexity
def complex_function():
    pass"""
        parser = SuppressionParser()
        suppressions = parser.parse(source)

        assert len(suppressions) == 1
        assert suppressions[0].rule_pattern == "maintainability/complexity"
        assert suppressions[0].line == 2  # Suppresses line 2
        assert suppressions[0].is_next_line is True

    def test_parse_file_suppression(self) -> None:
        """Test parsing file-level suppression comment."""
        source = """# parallax-ignore-file security/*
import os
def main():
    pass"""
        parser = SuppressionParser()
        suppressions = parser.parse(source)

        assert len(suppressions) == 1
        assert suppressions[0].rule_pattern == "security/*"
        assert suppressions[0].line is None
        assert suppressions[0].is_next_line is False

    def test_parse_multiple_suppressions(self) -> None:
        """Test parsing multiple suppression comments."""
        source = """# parallax-ignore-file testing/*
def func1():  # parallax-ignore security/hardcoded_secrets
    password = "secret"

# parallax-ignore-next-line maintainability/complexity
def func2():
    pass"""
        parser = SuppressionParser()
        suppressions = parser.parse(source)

        assert len(suppressions) == 3
        # File-level
        assert suppressions[0].rule_pattern == "testing/*"
        assert suppressions[0].line is None
        # Same-line
        assert suppressions[1].rule_pattern == "security/hardcoded_secrets"
        assert suppressions[1].line == 2
        # Next-line
        assert suppressions[2].rule_pattern == "maintainability/complexity"
        assert suppressions[2].line == 6

    def test_parse_case_insensitive(self) -> None:
        """Test that parsing is case-insensitive."""
        source = "x = 1  # PARALLAX-IGNORE security/test"
        parser = SuppressionParser()
        suppressions = parser.parse(source)

        assert len(suppressions) == 1
        assert suppressions[0].rule_pattern == "security/test"

    def test_parse_no_suppressions(self) -> None:
        """Test parsing code with no suppressions."""
        source = """def func():
    # This is a regular comment
    return 42"""
        parser = SuppressionParser()
        suppressions = parser.parse(source)

        assert len(suppressions) == 0

    def test_parse_wildcard_patterns(self) -> None:
        """Test parsing wildcard patterns."""
        source = """# parallax-ignore-file */*
# parallax-ignore security/*"""
        parser = SuppressionParser()
        suppressions = parser.parse(source)

        assert len(suppressions) == 2
        assert suppressions[0].rule_pattern == "*/*"
        assert suppressions[1].rule_pattern == "security/*"


class TestSuppressionChecker:
    """Tests for SuppressionChecker."""

    def test_exact_match_same_line(self) -> None:
        """Test exact rule match on same line."""
        suppressions = {
            "test.py": [
                Suppression(
                    rule_pattern="security/sql-injection",
                    line=10,
                    is_next_line=False,
                )
            ]
        }
        checker = SuppressionChecker(suppressions)

        assert checker.is_suppressed("test.py", 10, "security/sql-injection") is True
        assert checker.is_suppressed("test.py", 11, "security/sql-injection") is False
        assert checker.is_suppressed("test.py", 10, "security/xss") is False

    def test_wildcard_match(self) -> None:
        """Test wildcard pattern matching."""
        suppressions = {
            "test.py": [
                Suppression(
                    rule_pattern="security/*",
                    line=5,
                    is_next_line=False,
                )
            ]
        }
        checker = SuppressionChecker(suppressions)

        assert checker.is_suppressed("test.py", 5, "security/sql-injection") is True
        assert checker.is_suppressed("test.py", 5, "security/xss") is True
        assert checker.is_suppressed("test.py", 5, "maintainability/complexity") is False

    def test_file_level_suppression(self) -> None:
        """Test file-level suppression (line=None)."""
        suppressions = {
            "test.py": [
                Suppression(
                    rule_pattern="testing/*",
                    line=None,
                    is_next_line=False,
                )
            ]
        }
        checker = SuppressionChecker(suppressions)

        # Should suppress any line in the file
        assert checker.is_suppressed("test.py", 1, "testing/missing_test") is True
        assert checker.is_suppressed("test.py", 100, "testing/weak_assertion") is True
        # But not other lenses
        assert checker.is_suppressed("test.py", 1, "security/xss") is False

    def test_different_file_not_suppressed(self) -> None:
        """Test that suppressions only apply to their file."""
        suppressions = {
            "a.py": [
                Suppression(
                    rule_pattern="security/*",
                    line=None,
                    is_next_line=False,
                )
            ]
        }
        checker = SuppressionChecker(suppressions)

        assert checker.is_suppressed("a.py", 1, "security/xss") is True
        assert checker.is_suppressed("b.py", 1, "security/xss") is False

    def test_empty_suppressions(self) -> None:
        """Test with no suppressions."""
        checker = SuppressionChecker({})

        assert checker.is_suppressed("test.py", 1, "security/xss") is False

    def test_global_wildcard(self) -> None:
        """Test global wildcard pattern */*."""
        suppressions = {
            "test.py": [
                Suppression(
                    rule_pattern="*/*",
                    line=None,
                    is_next_line=False,
                )
            ]
        }
        checker = SuppressionChecker(suppressions)

        # Should suppress everything in that file
        assert checker.is_suppressed("test.py", 1, "security/xss") is True
        assert checker.is_suppressed("test.py", 1, "maintainability/complexity") is True
        assert checker.is_suppressed("test.py", 1, "testing/flaky_pattern") is True


class TestParseFileSuppressionsHelper:
    """Tests for the parse_file_suppressions helper function."""

    def test_helper_function(self) -> None:
        """Test the convenience function."""
        source = "x = 1  # parallax-ignore security/test"
        suppressions = parse_file_suppressions(source)

        assert len(suppressions) == 1
        assert suppressions[0].rule_pattern == "security/test"
