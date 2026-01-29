"""Testing lens for Parallax.

Detects testing issues like missing tests, weak assertions, and flaky patterns.
"""

import re
from typing import Any

from parallax.core.types import Annotation, Location, Severity
from parallax.lang.python import (
    find_function_calls,
    find_function_definitions,
    get_function_name,
)
from parallax.lenses.base import AnalysisContext, Lens, LensRegistry

# Weak assertion patterns
WEAK_ASSERTIONS = [
    "assertTrue(True)",
    "assertFalse(False)",
    "assertEqual(True, True)",
    "assertEqual(False, False)",
    "assert True",
    "assert 1",
    "assert not False",
]

# Flaky pattern indicators
FLAKY_PATTERNS = [
    r"time\.sleep\s*\(",
    r"asyncio\.sleep\s*\(",
    r"random\.",
    r"datetime\.now\s*\(",
    r"datetime\.utcnow\s*\(",
]


@LensRegistry.register
class TestingLens(Lens):
    """Test quality analysis lens."""

    def __init__(self) -> None:
        """Initialize the testing lens."""
        self._test_file_patterns = ["test_*.py", "*_test.py", "tests.py"]

    @property
    def name(self) -> str:
        return "testing"

    @property
    def description(self) -> str:
        return (
            "Detects testing issues like weak assertions, flaky patterns, and missing test coverage"
        )

    def configure(self, config: dict[str, Any]) -> None:
        """Configure lens from config."""
        if "test_file_patterns" in config:
            self._test_file_patterns = config["test_file_patterns"]

    def analyze(self, context: AnalysisContext) -> list[Annotation]:
        """Analyze code for testing issues."""
        annotations: list[Annotation] = []

        # Separate test files and source files
        test_files: set[str] = set()
        source_files: set[str] = set()

        for path in context.files.keys():
            if self._is_test_file(path):
                test_files.add(path)
            else:
                source_files.add(path)

        # Check test files for quality issues
        for path in test_files:
            ast = context.files[path]
            annotations.extend(self._check_weak_assertions(path, ast, context))
            annotations.extend(self._check_flaky_patterns(path, ast, context))

        # Check for missing tests
        annotations.extend(self._check_missing_tests(source_files, test_files, context))

        return annotations

    def _is_test_file(self, path: str) -> bool:
        """Check if a path is a test file."""
        import fnmatch
        from pathlib import Path

        filename = Path(path).name
        for pattern in self._test_file_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True

        # Also check if path contains 'tests/' or 'test/'
        return "/tests/" in path or "/test/" in path or path.startswith("tests/")

    def _check_weak_assertions(self, path: str, ast, context: AnalysisContext) -> list[Annotation]:
        """Check for weak assertions that always pass."""
        annotations = []

        # Find assertion calls
        assertion_methods = [
            "assertTrue",
            "assertFalse",
            "assertEqual",
            "assertNotEqual",
            "assertIs",
            "assertIsNot",
        ]

        for method in assertion_methods:
            calls = find_function_calls(ast, name=method)
            for call in calls:
                line = call.start_point[0] + 1

                if not context.is_line_changed(path, line):
                    continue

                call_text = ast.text_at(call)

                # Check for weak patterns
                for pattern in WEAK_ASSERTIONS:
                    if pattern in call_text:
                        annotations.append(
                            Annotation(
                                lens="testing",
                                rule="weak_assertion",
                                location=Location(
                                    file=path,
                                    start_line=line,
                                    end_line=call.end_point[0] + 1,
                                ),
                                severity=Severity.MEDIUM,
                                confidence=0.95,
                                message=f"Assertion always passes: {call_text.strip()[:50]}",
                                suggestion="Use meaningful assertions that test actual behavior",
                                category="test-quality",
                            )
                        )
                        break

        # Check for bare 'assert True' statements
        assert_stmts = ast.find_nodes_by_type("assert_statement")
        for stmt in assert_stmts:
            line = stmt.start_point[0] + 1

            if not context.is_line_changed(path, line):
                continue

            stmt_text = ast.text_at(stmt).strip()
            if stmt_text in ("assert True", "assert 1", "assert not False"):
                annotations.append(
                    Annotation(
                        lens="testing",
                        rule="weak_assertion",
                        location=Location(
                            file=path,
                            start_line=line,
                            end_line=line,
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.95,
                        message=f"Assertion always passes: {stmt_text}",
                        suggestion="Use meaningful assertions that test actual behavior",
                        category="test-quality",
                    )
                )

        return annotations

    def _check_flaky_patterns(self, path: str, ast, context: AnalysisContext) -> list[Annotation]:
        """Check for patterns that may cause flaky tests."""
        annotations = []

        # Get all the source text for regex matching
        source = ast.source.decode("utf-8")
        lines = source.split("\n")

        for i, line_text in enumerate(lines):
            line = i + 1  # 1-indexed

            if not context.is_line_changed(path, line):
                continue

            for pattern in FLAKY_PATTERNS:
                if re.search(pattern, line_text):
                    # Determine the specific issue
                    if "sleep" in pattern:
                        message = "Using sleep() in tests can cause flakiness"
                        suggestion = "Use mocking or polling with timeout instead of fixed sleeps"
                    elif "random" in pattern:
                        message = (
                            "Using random values in tests can cause non-deterministic failures"
                        )
                        suggestion = "Seed random generators or use fixed test data"
                    else:
                        message = "Using current time in tests can cause flakiness"
                        suggestion = "Use freezegun or mock time-dependent code"

                    annotations.append(
                        Annotation(
                            lens="testing",
                            rule="flaky_pattern",
                            location=Location(
                                file=path,
                                start_line=line,
                                end_line=line,
                            ),
                            severity=Severity.LOW,
                            confidence=0.7,
                            message=message,
                            suggestion=suggestion,
                            category="test-reliability",
                        )
                    )
                    break  # Only one annotation per line

        return annotations

    def _check_missing_tests(
        self,
        source_files: set[str],
        test_files: set[str],
        context: AnalysisContext,
    ) -> list[Annotation]:
        """Check for source changes without corresponding test changes."""
        annotations = []

        # Build a map of source file -> expected test file patterns
        for source_path in source_files:
            if source_path.endswith("__init__.py"):
                continue

            # Check if any test files were changed in this diff
            has_test_changes = len(test_files) > 0

            if not has_test_changes:
                # Get functions that were changed in this source file
                ast = context.files.get(source_path)
                if ast is None:
                    continue

                changed_functions = []
                functions = find_function_definitions(ast)
                for func in functions:
                    line = func.start_point[0] + 1
                    if context.is_line_changed(source_path, line):
                        func_name = get_function_name(func, ast)
                        if func_name and not func_name.startswith("_"):
                            changed_functions.append((func_name, line))

                # Flag each changed public function
                for func_name, line in changed_functions[:3]:  # Limit to avoid noise
                    annotations.append(
                        Annotation(
                            lens="testing",
                            rule="missing_test",
                            location=Location(
                                file=source_path,
                                start_line=line,
                                end_line=line,
                            ),
                            severity=Severity.INFO,
                            confidence=0.5,
                            message=f"Function '{func_name}' was changed but no test files were modified",
                            suggestion="Consider adding or updating tests for this change",
                            category="test-coverage",
                        )
                    )

        return annotations
