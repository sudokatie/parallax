"""Tests for lens base classes and registry."""

import pytest

from parallax.core.config import LensConfig
from parallax.core.types import Annotation, Location, Severity
from parallax.diff.types import DiffHunk, DiffLine, DiffLineKind, FileDiff, ParsedDiff
from parallax.lang.python import PythonAnalyzer
from parallax.lenses.base import AnalysisContext, Lens, LensRegistry


class TestAnalysisContext:
    """Tests for AnalysisContext."""

    def _create_context(self) -> AnalysisContext:
        """Create a test context."""
        # Create a simple diff
        lines = (
            DiffLine(kind=DiffLineKind.CONTEXT, content="x = 1", old_line=1, new_line=1),
            DiffLine(kind=DiffLineKind.ADD, content="y = 2", old_line=None, new_line=2),
            DiffLine(kind=DiffLineKind.ADD, content="z = 3", old_line=None, new_line=3),
        )
        hunk = DiffHunk(
            old_start=1, old_count=1, new_start=1, new_count=3, lines=lines, header="@@"
        )
        file_diff = FileDiff(old_path="test.py", new_path="test.py", hunks=(hunk,))
        diff = ParsedDiff(files=(file_diff,))

        # Create a simple AST
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("x = 1\ny = 2\nz = 3\n", path="test.py")

        config = LensConfig()
        return AnalysisContext(diff=diff, files={"test.py": ast}, config=config)

    def test_is_line_changed_true(self):
        """Test that changed lines are detected."""
        context = self._create_context()
        assert context.is_line_changed("test.py", 2) is True
        assert context.is_line_changed("test.py", 3) is True

    def test_is_line_changed_false(self):
        """Test that unchanged lines are not flagged."""
        context = self._create_context()
        assert context.is_line_changed("test.py", 1) is False
        assert context.is_line_changed("test.py", 100) is False

    def test_is_line_changed_wrong_file(self):
        """Test checking lines in a file not in the diff."""
        context = self._create_context()
        assert context.is_line_changed("other.py", 1) is False

    def test_get_file_existing(self):
        """Test getting an existing file."""
        context = self._create_context()
        ast = context.get_file("test.py")
        assert ast is not None
        assert ast.path == "test.py"

    def test_get_file_missing(self):
        """Test getting a missing file."""
        context = self._create_context()
        ast = context.get_file("other.py")
        assert ast is None


class TestLens:
    """Tests for Lens ABC."""

    def test_lens_is_abstract(self):
        """Test that Lens cannot be instantiated directly."""
        with pytest.raises(TypeError):
            Lens()

    def test_concrete_lens(self):
        """Test creating a concrete lens implementation."""

        class TestLens(Lens):
            @property
            def name(self) -> str:
                return "test"

            @property
            def description(self) -> str:
                return "Test lens"

            def analyze(self, context: AnalysisContext) -> list[Annotation]:
                return []

        lens = TestLens()
        assert lens.name == "test"
        assert lens.description == "Test lens"
        assert lens.analyze(None) == []

    def test_configure_default(self):
        """Test that configure has a default implementation."""

        class TestLens(Lens):
            @property
            def name(self) -> str:
                return "test"

            @property
            def description(self) -> str:
                return "Test lens"

            def analyze(self, context: AnalysisContext) -> list[Annotation]:
                return []

        lens = TestLens()
        # Should not raise
        lens.configure({"key": "value"})


class TestLensRegistry:
    """Tests for LensRegistry."""

    def setup_method(self):
        """Clear registry before each test."""
        LensRegistry.clear()

    def test_register_decorator(self):
        """Test registering a lens with decorator."""

        @LensRegistry.register
        class TestLens(Lens):
            @property
            def name(self) -> str:
                return "test"

            @property
            def description(self) -> str:
                return "Test lens"

            def analyze(self, context: AnalysisContext) -> list[Annotation]:
                return []

        assert LensRegistry.get("test") == TestLens

    def test_get_missing(self):
        """Test getting a lens that doesn't exist."""
        assert LensRegistry.get("nonexistent") is None

    def test_all_lenses(self):
        """Test getting all registered lenses."""

        @LensRegistry.register
        class LensA(Lens):
            @property
            def name(self) -> str:
                return "a"

            @property
            def description(self) -> str:
                return "Lens A"

            def analyze(self, context: AnalysisContext) -> list[Annotation]:
                return []

        @LensRegistry.register
        class LensB(Lens):
            @property
            def name(self) -> str:
                return "b"

            @property
            def description(self) -> str:
                return "Lens B"

            def analyze(self, context: AnalysisContext) -> list[Annotation]:
                return []

        all_lenses = LensRegistry.all()
        assert len(all_lenses) == 2
        assert LensA in all_lenses
        assert LensB in all_lenses

    def test_names(self):
        """Test getting all lens names."""

        @LensRegistry.register
        class LensA(Lens):
            @property
            def name(self) -> str:
                return "lens_a"

            @property
            def description(self) -> str:
                return "Lens A"

            def analyze(self, context: AnalysisContext) -> list[Annotation]:
                return []

        @LensRegistry.register
        class LensB(Lens):
            @property
            def name(self) -> str:
                return "lens_b"

            @property
            def description(self) -> str:
                return "Lens B"

            def analyze(self, context: AnalysisContext) -> list[Annotation]:
                return []

        names = LensRegistry.names()
        assert "lens_a" in names
        assert "lens_b" in names

    def test_clear(self):
        """Test clearing the registry."""

        @LensRegistry.register
        class TestLens(Lens):
            @property
            def name(self) -> str:
                return "test"

            @property
            def description(self) -> str:
                return "Test lens"

            def analyze(self, context: AnalysisContext) -> list[Annotation]:
                return []

        assert len(LensRegistry.all()) == 1
        LensRegistry.clear()
        assert len(LensRegistry.all()) == 0
