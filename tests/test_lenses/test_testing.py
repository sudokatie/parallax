"""Tests for the testing lens."""

import pytest

from parallax.core.config import LensConfig
from parallax.core.types import Severity
from parallax.diff.types import DiffHunk, DiffLine, DiffLineKind, FileDiff, ParsedDiff
from parallax.lang.python import PythonAnalyzer
from parallax.lenses.base import AnalysisContext
from parallax.lenses.testing import TestingLens


@pytest.fixture
def lens() -> TestingLens:
    """Create a testing lens instance."""
    return TestingLens()


@pytest.fixture
def analyzer() -> PythonAnalyzer:
    """Create a Python analyzer."""
    return PythonAnalyzer()


def make_context(
    files: dict[str, str],
    analyzer: PythonAnalyzer = None,
    config: dict = None,
) -> AnalysisContext:
    """Create an analysis context with given files as changed."""
    if analyzer is None:
        analyzer = PythonAnalyzer()

    parsed_files = {}
    file_diffs = []

    for path, source in files.items():
        if path.endswith(".py"):
            parsed_files[path] = analyzer.parse_source(source)

        lines = source.split("\n")
        diff_lines = [
            DiffLine(kind=DiffLineKind.ADD, content=line, old_line=None, new_line=i + 1)
            for i, line in enumerate(lines)
        ]
        hunk = DiffHunk(
            old_start=0,
            old_count=0,
            new_start=1,
            new_count=len(lines),
            lines=tuple(diff_lines),
            header="@@ -0,0 +1,{} @@".format(len(lines)),
        )
        file_diffs.append(
            FileDiff(
                old_path=None,
                new_path=path,
                hunks=(hunk,),
                is_binary=False,
            )
        )

    diff = ParsedDiff(files=tuple(file_diffs))

    return AnalysisContext(
        diff=diff,
        files=parsed_files,
        config=LensConfig(
            enabled=True,
            severity_threshold=Severity.INFO,
            rules=config or {},
        ),
    )


class TestWeakAssertion:
    """Tests for weak assertion detection."""

    def test_assert_true_detected(self, lens: TestingLens) -> None:
        """Test that assertTrue(True) is detected."""
        source = """import unittest

class TestFoo(unittest.TestCase):
    def test_always_passes(self):
        self.assertTrue(True)
"""
        context = make_context({"tests/test_foo.py": source})
        annotations = lens.analyze(context)

        weak_findings = [a for a in annotations if a.rule == "weak_assertion"]
        assert len(weak_findings) == 1
        assert "always passes" in weak_findings[0].message.lower()

    def test_assert_false_false_detected(self, lens: TestingLens) -> None:
        """Test that assertFalse(False) is detected."""
        source = """import unittest

class TestFoo(unittest.TestCase):
    def test_pointless(self):
        self.assertFalse(False)
"""
        context = make_context({"tests/test_foo.py": source})
        annotations = lens.analyze(context)

        weak_findings = [a for a in annotations if a.rule == "weak_assertion"]
        assert len(weak_findings) == 1

    def test_bare_assert_true_detected(self, lens: TestingLens) -> None:
        """Test that bare 'assert True' is detected."""
        source = """def test_something():
    assert True
"""
        context = make_context({"test_foo.py": source})
        annotations = lens.analyze(context)

        weak_findings = [a for a in annotations if a.rule == "weak_assertion"]
        assert len(weak_findings) == 1

    def test_valid_assertion_not_flagged(self, lens: TestingLens) -> None:
        """Test that valid assertions aren't flagged."""
        source = """def test_something():
    result = compute()
    assert result == 42
    self.assertTrue(condition)
    self.assertEqual(a, b)
"""
        context = make_context({"test_foo.py": source})
        annotations = lens.analyze(context)

        weak_findings = [a for a in annotations if a.rule == "weak_assertion"]
        assert len(weak_findings) == 0


class TestFlakyPattern:
    """Tests for flaky pattern detection."""

    def test_time_sleep_detected(self, lens: TestingLens) -> None:
        """Test that time.sleep() in tests is detected."""
        source = """import time

def test_with_sleep():
    do_something()
    time.sleep(1)
    check_result()
"""
        context = make_context({"test_foo.py": source})
        annotations = lens.analyze(context)

        flaky_findings = [a for a in annotations if a.rule == "flaky_pattern"]
        assert len(flaky_findings) == 1
        assert "sleep" in flaky_findings[0].message.lower()

    def test_asyncio_sleep_detected(self, lens: TestingLens) -> None:
        """Test that asyncio.sleep() in tests is detected."""
        source = """import asyncio

async def test_async():
    await asyncio.sleep(0.5)
"""
        context = make_context({"test_foo.py": source})
        annotations = lens.analyze(context)

        flaky_findings = [a for a in annotations if a.rule == "flaky_pattern"]
        assert len(flaky_findings) == 1

    def test_random_detected(self, lens: TestingLens) -> None:
        """Test that random.* in tests is detected."""
        source = """import random

def test_random_data():
    value = random.randint(1, 100)
    assert value > 0
"""
        context = make_context({"test_foo.py": source})
        annotations = lens.analyze(context)

        flaky_findings = [a for a in annotations if a.rule == "flaky_pattern"]
        assert len(flaky_findings) == 1
        assert "random" in flaky_findings[0].message.lower()

    def test_datetime_now_detected(self, lens: TestingLens) -> None:
        """Test that datetime.now() in tests is detected."""
        source = """from datetime import datetime

def test_timing():
    start = datetime.now()
    do_work()
    assert datetime.now() > start
"""
        context = make_context({"test_foo.py": source})
        annotations = lens.analyze(context)

        flaky_findings = [a for a in annotations if a.rule == "flaky_pattern"]
        assert len(flaky_findings) >= 1

    def test_non_test_file_not_checked(self, lens: TestingLens) -> None:
        """Test that flaky patterns in non-test files aren't flagged."""
        source = """import time

def slow_operation():
    time.sleep(1)
"""
        context = make_context({"src/utils.py": source})
        annotations = lens.analyze(context)

        flaky_findings = [a for a in annotations if a.rule == "flaky_pattern"]
        assert len(flaky_findings) == 0


class TestMissingTest:
    """Tests for missing test detection."""

    def test_source_change_without_test_change(self, lens: TestingLens) -> None:
        """Test that source changes without test changes are flagged."""
        source = """def public_function():
    return 42
"""
        context = make_context({"src/module.py": source})
        annotations = lens.analyze(context)

        missing_findings = [a for a in annotations if a.rule == "missing_test"]
        assert len(missing_findings) >= 1
        assert "public_function" in missing_findings[0].message

    def test_source_change_with_test_change_not_flagged(self, lens: TestingLens) -> None:
        """Test that source changes with test changes aren't flagged."""
        source = """def public_function():
    return 42
"""
        test_source = """def test_public_function():
    assert public_function() == 42
"""
        context = make_context({
            "src/module.py": source,
            "tests/test_module.py": test_source,
        })
        annotations = lens.analyze(context)

        missing_findings = [a for a in annotations if a.rule == "missing_test"]
        assert len(missing_findings) == 0

    def test_private_function_not_flagged(self, lens: TestingLens) -> None:
        """Test that private function changes without tests aren't flagged."""
        source = """def _private_helper():
    return 42
"""
        context = make_context({"src/module.py": source})
        annotations = lens.analyze(context)

        missing_findings = [a for a in annotations if a.rule == "missing_test"]
        assert len(missing_findings) == 0

    def test_init_file_not_flagged(self, lens: TestingLens) -> None:
        """Test that __init__.py changes aren't flagged."""
        source = """from .module import func
"""
        context = make_context({"src/__init__.py": source})
        annotations = lens.analyze(context)

        missing_findings = [a for a in annotations if a.rule == "missing_test"]
        assert len(missing_findings) == 0


class TestFileDetection:
    """Tests for test file detection."""

    def test_test_prefix_detected(self, lens: TestingLens) -> None:
        """Test that test_*.py files are detected as test files."""
        assert lens._is_test_file("test_foo.py") is True
        assert lens._is_test_file("tests/test_bar.py") is True

    def test_test_suffix_detected(self, lens: TestingLens) -> None:
        """Test that *_test.py files are detected as test files."""
        assert lens._is_test_file("foo_test.py") is True
        assert lens._is_test_file("tests/bar_test.py") is True

    def test_tests_directory_detected(self, lens: TestingLens) -> None:
        """Test that files in tests/ directory are detected."""
        assert lens._is_test_file("tests/conftest.py") is True
        assert lens._is_test_file("path/to/tests/helpers.py") is True

    def test_source_files_not_detected(self, lens: TestingLens) -> None:
        """Test that source files aren't detected as test files."""
        assert lens._is_test_file("src/module.py") is False
        assert lens._is_test_file("utils.py") is False
        assert lens._is_test_file("testing_utils.py") is False  # Not a test file


class TestConfiguration:
    """Tests for lens configuration."""

    def test_custom_test_patterns(self, lens: TestingLens) -> None:
        """Test configuring custom test file patterns."""
        lens.configure({"test_file_patterns": ["spec_*.py", "*_spec.py"]})

        assert lens._is_test_file("spec_foo.py") is True
        assert lens._is_test_file("foo_spec.py") is True
        # Default patterns should no longer match
        assert lens._is_test_file("test_foo.py") is False
