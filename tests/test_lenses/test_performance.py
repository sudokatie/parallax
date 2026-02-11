"""Tests for performance lens."""

import pytest

from parallax.core.config import LensConfig
from parallax.core.types import Severity
from parallax.diff.types import DiffHunk, DiffLine, DiffLineKind, FileDiff, ParsedDiff
from parallax.lang.python import PythonAnalyzer
from parallax.lenses.base import AnalysisContext, LensRegistry
from parallax.lenses.performance import PerformanceLens


def create_context(source: str, changed_lines: list[int] | None = None) -> AnalysisContext:
    """Create a test context with the given source and changed lines."""
    source_lines = source.split("\n")

    if changed_lines is None:
        changed_lines = list(range(1, len(source_lines) + 1))

    lines = []
    for i, content in enumerate(source_lines):
        line_num = i + 1
        if line_num in changed_lines:
            lines.append(
                DiffLine(kind=DiffLineKind.ADD, content=content, old_line=None, new_line=line_num)
            )
        else:
            lines.append(
                DiffLine(
                    kind=DiffLineKind.CONTEXT, content=content, old_line=line_num, new_line=line_num
                )
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

    analyzer = PythonAnalyzer()
    ast = analyzer.parse_source(source, path="test.py")

    return AnalysisContext(diff=diff, files={"test.py": ast}, config=LensConfig())


class TestPerformanceLensRegistration:
    """Tests for performance lens registration."""

    def test_lens_registered(self):
        """Test that performance lens can be instantiated."""
        lens = PerformanceLens()
        assert lens.name == "performance"

    def test_lens_properties(self):
        """Test lens name and description."""
        lens = PerformanceLens()
        assert lens.name == "performance"
        assert "performance" in lens.description.lower()


class TestNPlusOneDetection:
    """Tests for N+1 query pattern detection."""

    def test_detect_query_in_loop(self):
        """Test detecting ORM query inside a loop."""
        source = """
for user in users:
    posts = Post.objects.filter(author=user)
    print(posts)
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        n_plus_one = [a for a in annotations if a.rule == "n_plus_one"]
        assert len(n_plus_one) == 1
        assert n_plus_one[0].severity == Severity.HIGH
        assert "prefetch" in n_plus_one[0].suggestion.lower()

    def test_no_false_positive_query_outside_loop(self):
        """Test that queries outside loops don't trigger."""
        source = """
users = User.objects.filter(active=True)
for user in users:
    print(user.name)
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        n_plus_one = [a for a in annotations if a.rule == "n_plus_one"]
        assert len(n_plus_one) == 0


class TestStringConcatInLoop:
    """Tests for string concatenation in loop detection."""

    def test_detect_string_concat_with_literal(self):
        """Test detecting += with string literal in loop."""
        source = """
result = ""
for item in items:
    result += "prefix: " + str(item)
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        concat = [a for a in annotations if a.rule == "string_concat_loop"]
        assert len(concat) == 1
        assert concat[0].severity == Severity.MEDIUM
        assert "join" in concat[0].suggestion.lower()

    def test_detect_string_concat_fstring(self):
        """Test detecting += with f-string in loop."""
        source = """
result = ""
for i in range(100):
    result += f"item {i}\\n"
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        concat = [a for a in annotations if a.rule == "string_concat_loop"]
        assert len(concat) == 1

    def test_no_false_positive_numeric_concat(self):
        """Test that numeric += doesn't trigger."""
        source = """
total = 0
for num in numbers:
    total += num
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        concat = [a for a in annotations if a.rule == "string_concat_loop"]
        assert len(concat) == 0


class TestListVsGenerator:
    """Tests for list comprehension vs generator expression."""

    def test_detect_list_comp_in_sum(self):
        """Test detecting list comprehension in sum()."""
        source = """
total = sum([x * 2 for x in range(1000)])
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        gen = [a for a in annotations if a.rule == "list_vs_generator"]
        assert len(gen) == 1
        assert gen[0].severity == Severity.LOW
        assert "generator" in gen[0].suggestion.lower()

    def test_detect_list_comp_in_any(self):
        """Test detecting list comprehension in any()."""
        source = """
has_even = any([x % 2 == 0 for x in numbers])
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        gen = [a for a in annotations if a.rule == "list_vs_generator"]
        assert len(gen) == 1

    def test_no_false_positive_assigned_list(self):
        """Test that assigned list comprehensions don't trigger."""
        source = """
doubled = [x * 2 for x in range(100)]
total = sum(doubled)
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        gen = [a for a in annotations if a.rule == "list_vs_generator"]
        assert len(gen) == 0


class TestUnboundedLoop:
    """Tests for unbounded loop detection."""

    def test_detect_while_true_no_break(self):
        """Test detecting while True without break."""
        source = """
while True:
    process()
    continue
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        unbounded = [a for a in annotations if a.rule == "unbounded_loop"]
        assert len(unbounded) == 1
        assert unbounded[0].severity == Severity.MEDIUM

    def test_no_false_positive_while_true_with_break(self):
        """Test that while True with break doesn't trigger."""
        source = """
while True:
    data = read()
    if not data:
        break
    process(data)
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        unbounded = [a for a in annotations if a.rule == "unbounded_loop"]
        assert len(unbounded) == 0

    def test_no_false_positive_while_true_with_return(self):
        """Test that while True with return doesn't trigger."""
        source = """
def server():
    while True:
        conn = accept()
        if shutdown:
            return
        handle(conn)
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        unbounded = [a for a in annotations if a.rule == "unbounded_loop"]
        assert len(unbounded) == 0


class TestLargeAllocation:
    """Tests for large allocation detection."""

    def test_detect_list_of_range(self):
        """Test detecting list(range(...))."""
        source = """
numbers = list(range(1000))
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        alloc = [a for a in annotations if a.rule == "large_allocation"]
        assert len(alloc) == 1
        assert "iterate" in alloc[0].suggestion.lower()

    def test_detect_very_large_range(self):
        """Test detecting range with large literal."""
        source = """
for i in range(100000000):
    pass
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        alloc = [a for a in annotations if a.rule == "large_allocation"]
        assert len(alloc) == 1
        assert "memory" in alloc[0].message.lower()


class TestRepeatedComputation:
    """Tests for repeated computation detection."""

    def test_detect_range_len(self):
        """Test detecting range(len(x)) antipattern."""
        source = """
for i in range(len(items)):
    print(items[i])
"""
        context = create_context(source)
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        repeated = [a for a in annotations if a.rule == "repeated_computation"]
        assert len(repeated) == 1
        assert "enumerate" in repeated[0].suggestion.lower()


class TestChangedLinesOnly:
    """Tests that lens only flags changed lines."""

    def test_only_flags_changed_lines(self):
        """Test that unchanged lines are not flagged."""
        source = """
# Line 1
for user in users:
    Post.objects.filter(author=user)
# Line 4
"""
        # Only line 1 and 4 changed (comments), not the loop
        context = create_context(source, changed_lines=[1, 4])
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        # Should not flag the N+1 since the for loop line wasn't changed
        assert len(annotations) == 0

    def test_flags_when_line_changed(self):
        """Test that changed lines are flagged."""
        source = """
# Line 1
for user in users:
    Post.objects.filter(author=user)
# Line 4
"""
        # Loop line is line 3 (after leading newline and comment)
        context = create_context(source, changed_lines=[3])
        lens = PerformanceLens()
        annotations = lens.analyze(context)

        n_plus_one = [a for a in annotations if a.rule == "n_plus_one"]
        assert len(n_plus_one) == 1
