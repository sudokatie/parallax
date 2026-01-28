"""Tests for the maintainability lens."""

import pytest

from parallax.core.config import LensConfig
from parallax.core.types import Severity
from parallax.diff.types import DiffHunk, DiffLine, DiffLineKind, FileDiff, ParsedDiff
from parallax.lang.python import PythonAnalyzer
from parallax.lenses.base import AnalysisContext
from parallax.lenses.maintainability import MaintainabilityLens


@pytest.fixture
def lens() -> MaintainabilityLens:
    """Create a maintainability lens instance."""
    return MaintainabilityLens()


@pytest.fixture
def analyzer() -> PythonAnalyzer:
    """Create a Python analyzer."""
    return PythonAnalyzer()


def make_context(
    source: str,
    path: str = "test.py",
    analyzer: PythonAnalyzer = None,
    config: dict = None,
) -> AnalysisContext:
    """Create an analysis context with the given source as a changed file."""
    if analyzer is None:
        analyzer = PythonAnalyzer()

    ast = analyzer.parse_source(source)
    lines = source.split("\n")

    # Create diff that marks all lines as changed
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
    file_diff = FileDiff(
        old_path=None,
        new_path=path,
        hunks=(hunk,),
        is_binary=False,
    )
    diff = ParsedDiff(files=(file_diff,))

    return AnalysisContext(
        diff=diff,
        files={path: ast},
        config=LensConfig(
            enabled=True,
            severity_threshold=Severity.INFO,
            rules=config or {},
        ),
    )


class TestCyclomaticComplexity:
    """Tests for cyclomatic complexity detection."""

    def test_simple_function_no_finding(self, lens: MaintainabilityLens) -> None:
        """Test that simple functions don't trigger findings."""
        source = """def simple():
    return 42
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        complexity_findings = [a for a in annotations if a.rule == "cyclomatic_complexity"]
        assert len(complexity_findings) == 0

    def test_complex_function_triggers_finding(self, lens: MaintainabilityLens) -> None:
        """Test that complex functions trigger findings."""
        # Create a function with high complexity (many if statements)
        source = """def complex_function(a, b, c, d, e, f, g, h, i, j, k):
    if a:
        return 1
    elif b:
        return 2
    elif c:
        return 3
    elif d:
        return 4
    elif e:
        return 5
    elif f:
        return 6
    elif g:
        return 7
    elif h:
        return 8
    elif i:
        return 9
    elif j:
        return 10
    elif k:
        return 11
    else:
        return 0
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        complexity_findings = [a for a in annotations if a.rule == "cyclomatic_complexity"]
        assert len(complexity_findings) == 1
        assert "complex_function" in complexity_findings[0].message
        assert complexity_findings[0].severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)

    def test_configurable_threshold(self, lens: MaintainabilityLens) -> None:
        """Test that complexity threshold is configurable."""
        source = """def moderate():
    if a:
        return 1
    elif b:
        return 2
    elif c:
        return 3
    else:
        return 0
"""
        # With default threshold (10), this shouldn't trigger
        context = make_context(source)
        annotations = lens.analyze(context)
        assert len([a for a in annotations if a.rule == "cyclomatic_complexity"]) == 0

        # With lower threshold (2), it should trigger
        lens.configure({"cyclomatic_complexity": {"threshold": 2}})
        annotations = lens.analyze(context)
        assert len([a for a in annotations if a.rule == "cyclomatic_complexity"]) == 1


class TestFunctionLength:
    """Tests for function length detection."""

    def test_short_function_no_finding(self, lens: MaintainabilityLens) -> None:
        """Test that short functions don't trigger findings."""
        source = """def short():
    x = 1
    y = 2
    return x + y
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        length_findings = [a for a in annotations if a.rule == "function_length"]
        assert len(length_findings) == 0

    def test_long_function_triggers_finding(self, lens: MaintainabilityLens) -> None:
        """Test that long functions trigger findings."""
        # Configure a low threshold for testing
        lens.configure({"function_length": {"max_lines": 5}})

        source = """def long_function():
    a = 1
    b = 2
    c = 3
    d = 4
    e = 5
    f = 6
    g = 7
    return a + b + c + d + e + f + g
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        length_findings = [a for a in annotations if a.rule == "function_length"]
        assert len(length_findings) == 1
        assert "long_function" in length_findings[0].message


class TestParameterCount:
    """Tests for parameter count detection."""

    def test_few_parameters_no_finding(self, lens: MaintainabilityLens) -> None:
        """Test that functions with few parameters don't trigger findings."""
        source = """def normal(a, b, c):
    return a + b + c
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        param_findings = [a for a in annotations if a.rule == "parameter_count"]
        assert len(param_findings) == 0

    def test_many_parameters_triggers_finding(self, lens: MaintainabilityLens) -> None:
        """Test that functions with many parameters trigger findings."""
        source = """def too_many(a, b, c, d, e, f, g, h):
    return a + b + c + d + e + f + g + h
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        param_findings = [a for a in annotations if a.rule == "parameter_count"]
        assert len(param_findings) == 1
        assert "too_many" in param_findings[0].message

    def test_self_not_counted(self, lens: MaintainabilityLens) -> None:
        """Test that self/cls parameters are not counted."""
        lens.configure({"parameter_count": {"max_params": 3}})

        source = """class MyClass:
    def method(self, a, b, c):
        return a + b + c
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        param_findings = [a for a in annotations if a.rule == "parameter_count"]
        assert len(param_findings) == 0  # self not counted, so only 3 params


class TestMagicNumber:
    """Tests for magic number detection."""

    def test_acceptable_numbers_no_finding(self, lens: MaintainabilityLens) -> None:
        """Test that common acceptable numbers don't trigger findings."""
        source = """def func():
    x = 0
    y = 1
    z = -1
    a = 100
    b = 60  # seconds
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        magic_findings = [a for a in annotations if a.rule == "magic_number"]
        assert len(magic_findings) == 0

    def test_magic_number_triggers_finding(self, lens: MaintainabilityLens) -> None:
        """Test that unusual numbers trigger findings."""
        source = """def func():
    x = 42
    y = 1337
    z = 3.14159
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        magic_findings = [a for a in annotations if a.rule == "magic_number"]
        assert len(magic_findings) >= 1  # At least one magic number detected

    def test_constants_not_flagged(self, lens: MaintainabilityLens) -> None:
        """Test that UPPER_CASE constant assignments aren't flagged."""
        source = """MAX_RETRIES = 42
_INTERNAL_VALUE = 1337
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        magic_findings = [a for a in annotations if a.rule == "magic_number"]
        assert len(magic_findings) == 0


class TestDeepNesting:
    """Tests for deep nesting detection."""

    def test_shallow_nesting_no_finding(self, lens: MaintainabilityLens) -> None:
        """Test that shallow nesting doesn't trigger findings."""
        source = """def func():
    if condition:
        for item in items:
            process(item)
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        nesting_findings = [a for a in annotations if a.rule == "deep_nesting"]
        assert len(nesting_findings) == 0

    def test_deep_nesting_triggers_finding(self, lens: MaintainabilityLens) -> None:
        """Test that deep nesting triggers findings."""
        lens.configure({"deep_nesting": {"max_depth": 3}})

        source = """def deeply_nested():
    if a:
        if b:
            if c:
                if d:
                    if e:
                        do_something()
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        nesting_findings = [a for a in annotations if a.rule == "deep_nesting"]
        assert len(nesting_findings) == 1
        assert "deeply_nested" in nesting_findings[0].message
        assert "5" in nesting_findings[0].message  # 5 levels deep

    def test_various_nesting_constructs(self, lens: MaintainabilityLens) -> None:
        """Test that various control structures count towards nesting."""
        lens.configure({"deep_nesting": {"max_depth": 2}})

        source = """def mixed_nesting():
    if condition:
        for item in items:
            while running:
                try:
                    process()
                except:
                    handle()
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        nesting_findings = [a for a in annotations if a.rule == "deep_nesting"]
        assert len(nesting_findings) == 1

    def test_configurable_max_depth(self, lens: MaintainabilityLens) -> None:
        """Test that max nesting depth is configurable."""
        source = """def nested():
    if a:
        if b:
            if c:
                pass
"""
        # With default threshold (4), this shouldn't trigger (only 3 levels)
        context = make_context(source)
        annotations = lens.analyze(context)
        assert len([a for a in annotations if a.rule == "deep_nesting"]) == 0

        # With lower threshold (2), it should trigger
        lens.configure({"deep_nesting": {"max_depth": 2}})
        annotations = lens.analyze(context)
        assert len([a for a in annotations if a.rule == "deep_nesting"]) == 1


class TestDuplicateCode:
    """Tests for duplicate code detection."""

    def test_detect_duplicate_functions(self, lens: MaintainabilityLens) -> None:
        """Test detecting duplicate function bodies."""
        source = """def function_a():
    x = 1
    y = 2
    z = 3
    result = x + y + z
    return result

def function_b():
    x = 1
    y = 2
    z = 3
    result = x + y + z
    return result
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        dup_findings = [a for a in annotations if a.rule == "duplicate_code"]
        assert len(dup_findings) == 1
        assert "function_b" in dup_findings[0].message or "function_a" in dup_findings[0].message

    def test_no_flag_short_functions(self, lens: MaintainabilityLens) -> None:
        """Test that short functions are not flagged as duplicates."""
        source = """def short_a():
    return 1

def short_b():
    return 1
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        dup_findings = [a for a in annotations if a.rule == "duplicate_code"]
        assert len(dup_findings) == 0

    def test_no_flag_different_bodies(self, lens: MaintainabilityLens) -> None:
        """Test that different function bodies are not flagged."""
        source = """def func_a():
    x = 1
    y = 2
    z = 3
    result = x + y + z
    return result

def func_b():
    a = 10
    b = 20
    c = 30
    total = a * b * c
    return total
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        dup_findings = [a for a in annotations if a.rule == "duplicate_code"]
        assert len(dup_findings) == 0


class TestDeadCode:
    """Tests for dead code detection."""

    def test_detect_code_after_return(self, lens: MaintainabilityLens) -> None:
        """Test detecting code after return statement."""
        source = """def func():
    return 42
    x = 1  # Dead code
    print(x)  # Also dead
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        dead_findings = [a for a in annotations if a.rule == "dead_code"]
        assert len(dead_findings) >= 1
        assert dead_findings[0].message.startswith("Unreachable code")

    def test_detect_code_after_raise(self, lens: MaintainabilityLens) -> None:
        """Test detecting code after raise statement."""
        source = """def func():
    raise ValueError("error")
    cleanup()  # Dead code
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        dead_findings = [a for a in annotations if a.rule == "dead_code"]
        assert len(dead_findings) >= 1

    def test_no_flag_code_before_return(self, lens: MaintainabilityLens) -> None:
        """Test that code before return is not flagged."""
        source = """def func():
    x = 1
    y = 2
    return x + y
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        dead_findings = [a for a in annotations if a.rule == "dead_code"]
        assert len(dead_findings) == 0

    def test_no_flag_conditional_return(self, lens: MaintainabilityLens) -> None:
        """Test that code after conditional return is not flagged."""
        source = """def func(condition):
    if condition:
        return 1
    return 2  # Not dead - only reached if condition is false
"""
        context = make_context(source)
        annotations = lens.analyze(context)

        dead_findings = [a for a in annotations if a.rule == "dead_code"]
        assert len(dead_findings) == 0


class TestConfiguration:
    """Tests for lens configuration."""

    def test_configure_all_thresholds(self, lens: MaintainabilityLens) -> None:
        """Test configuring all thresholds."""
        lens.configure({
            "cyclomatic_complexity": {"threshold": 5},
            "function_length": {"max_lines": 20},
            "parameter_count": {"max_params": 3},
            "deep_nesting": {"max_depth": 2},
        })

        assert lens._complexity_threshold == 5
        assert lens._max_function_lines == 20
        assert lens._max_parameters == 3
        assert lens._max_nesting == 2

    def test_partial_configuration(self, lens: MaintainabilityLens) -> None:
        """Test that partial config only updates specified values."""
        original_complexity = lens._complexity_threshold
        original_params = lens._max_parameters

        lens.configure({"function_length": {"max_lines": 30}})

        assert lens._complexity_threshold == original_complexity
        assert lens._max_parameters == original_params
        assert lens._max_function_lines == 30
