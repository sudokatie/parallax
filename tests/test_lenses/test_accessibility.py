"""Tests for accessibility lens."""

import pytest

from parallax.core.config import LensConfig
from parallax.core.types import Severity
from parallax.diff.types import DiffHunk, DiffLine, DiffLineKind, FileDiff, ParsedDiff
from parallax.lang.javascript import JavaScriptAnalyzer
from parallax.lenses.accessibility import AccessibilityLens
from parallax.lenses.base import AnalysisContext


def create_context(source: str, path: str = "test.jsx") -> AnalysisContext:
    """Create an AnalysisContext for testing."""
    analyzer = JavaScriptAnalyzer()
    ast = analyzer.parse_source(source, path)

    # Create a diff that marks all lines as changed
    lines = source.split("\n")
    diff_lines = tuple(
        DiffLine(kind=DiffLineKind.ADD, content=line, old_line=None, new_line=i + 1)
        for i, line in enumerate(lines)
    )
    hunk = DiffHunk(
        old_start=0, old_count=0, new_start=1, new_count=len(lines),
        lines=diff_lines, header="@@ -0,0 +1,%d @@" % len(lines)
    )
    file_diff = FileDiff(old_path=None, new_path=path, hunks=(hunk,), is_binary=False)
    parsed_diff = ParsedDiff(files=(file_diff,))

    return AnalysisContext(diff=parsed_diff, files={path: ast}, config=LensConfig())


class TestMissingAltText:
    """Tests for missing alt text detection."""

    def test_img_missing_alt(self):
        """Test detecting img without alt attribute."""
        lens = AccessibilityLens()
        source = '<img src="photo.jpg">'
        context = create_context(source)

        annotations = lens.analyze(context)

        assert len(annotations) == 1
        assert annotations[0].rule == "missing_alt_text"
        assert annotations[0].severity == Severity.HIGH

    def test_img_with_alt(self):
        """Test that img with alt passes."""
        lens = AccessibilityLens()
        source = '<img src="photo.jpg" alt="A photo">'
        context = create_context(source)

        annotations = lens.analyze(context)

        # Should have no missing_alt_text annotations
        alt_annotations = [a for a in annotations if a.rule == "missing_alt_text"]
        assert len(alt_annotations) == 0

    def test_img_empty_alt_info(self):
        """Test that empty alt is flagged as info."""
        lens = AccessibilityLens()
        source = '<img src="decoration.jpg" alt="">'
        context = create_context(source)

        annotations = lens.analyze(context)

        empty_alt = [a for a in annotations if a.rule == "empty_alt_text"]
        assert len(empty_alt) == 1
        assert empty_alt[0].severity == Severity.INFO

    def test_img_empty_alt_decorative_ok(self):
        """Test that empty alt with role=presentation is not flagged."""
        lens = AccessibilityLens()
        source = '<img src="decoration.jpg" alt="" role="presentation">'
        context = create_context(source)

        annotations = lens.analyze(context)

        empty_alt = [a for a in annotations if a.rule == "empty_alt_text"]
        assert len(empty_alt) == 0

    def test_jsx_img_missing_alt(self):
        """Test detecting JSX img without alt."""
        lens = AccessibilityLens()
        source = '<img src={photoUrl} />'
        context = create_context(source)

        annotations = lens.analyze(context)

        assert len(annotations) >= 1
        alt_missing = [a for a in annotations if a.rule == "missing_alt_text"]
        assert len(alt_missing) >= 1


class TestButtonLabels:
    """Tests for button label detection."""

    def test_icon_button_missing_label(self):
        """Test detecting icon button without aria-label."""
        lens = AccessibilityLens()
        source = '<button class="icon-btn"><svg></svg></button>'
        context = create_context(source)

        annotations = lens.analyze(context)

        btn_annotations = [a for a in annotations if a.rule == "missing_button_label"]
        assert len(btn_annotations) == 1
        assert btn_annotations[0].severity == Severity.MEDIUM

    def test_icon_button_with_label(self):
        """Test that button with aria-label passes."""
        lens = AccessibilityLens()
        source = '<button class="icon-btn" aria-label="Close"><svg></svg></button>'
        context = create_context(source)

        annotations = lens.analyze(context)

        btn_annotations = [a for a in annotations if a.rule == "missing_button_label"]
        assert len(btn_annotations) == 0

    def test_button_with_text(self):
        """Test that button with text content passes."""
        lens = AccessibilityLens()
        source = '<button>Submit</button>'
        context = create_context(source)

        annotations = lens.analyze(context)

        btn_annotations = [a for a in annotations if a.rule == "missing_button_label"]
        # Text button shouldn't be flagged (doesn't have icon indicators)
        assert len(btn_annotations) == 0


class TestEmptyLinks:
    """Tests for empty link detection."""

    def test_link_with_only_image(self):
        """Test detecting link with only an image."""
        lens = AccessibilityLens()
        source = '<a href="/home"><img src="logo.png"></a>'
        context = create_context(source)

        annotations = lens.analyze(context)

        link_annotations = [a for a in annotations if a.rule == "empty_link"]
        assert len(link_annotations) == 1
        assert link_annotations[0].severity == Severity.HIGH

    def test_link_with_text(self):
        """Test that link with text passes."""
        lens = AccessibilityLens()
        source = '<a href="/home">Home</a>'
        context = create_context(source)

        annotations = lens.analyze(context)

        link_annotations = [a for a in annotations if a.rule == "empty_link"]
        assert len(link_annotations) == 0

    def test_link_with_aria_label(self):
        """Test that image link with aria-label passes."""
        lens = AccessibilityLens()
        source = '<a href="/home" aria-label="Go to homepage"><img src="logo.png"></a>'
        context = create_context(source)

        annotations = lens.analyze(context)

        link_annotations = [a for a in annotations if a.rule == "empty_link"]
        assert len(link_annotations) == 0


class TestFormLabels:
    """Tests for form label detection."""

    def test_input_missing_label(self):
        """Test detecting input without label."""
        lens = AccessibilityLens()
        source = '<input type="text" name="email">'
        context = create_context(source)

        annotations = lens.analyze(context)

        form_annotations = [a for a in annotations if a.rule == "missing_form_label"]
        assert len(form_annotations) == 1
        assert form_annotations[0].severity == Severity.MEDIUM

    def test_input_with_label(self):
        """Test that input with matching label passes."""
        lens = AccessibilityLens()
        source = """
<label for="email">Email</label>
<input type="text" id="email" name="email">
"""
        context = create_context(source)

        annotations = lens.analyze(context)

        form_annotations = [a for a in annotations if a.rule == "missing_form_label"]
        assert len(form_annotations) == 0

    def test_input_with_aria_label(self):
        """Test that input with aria-label passes."""
        lens = AccessibilityLens()
        source = '<input type="text" aria-label="Email address">'
        context = create_context(source)

        annotations = lens.analyze(context)

        form_annotations = [a for a in annotations if a.rule == "missing_form_label"]
        assert len(form_annotations) == 0

    def test_input_placeholder_only(self):
        """Test that placeholder-only input is flagged as low severity."""
        lens = AccessibilityLens()
        source = '<input type="text" placeholder="Enter email">'
        context = create_context(source)

        annotations = lens.analyze(context)

        placeholder_annotations = [a for a in annotations if a.rule == "placeholder_only_label"]
        assert len(placeholder_annotations) == 1
        assert placeholder_annotations[0].severity == Severity.LOW

    def test_hidden_input_not_flagged(self):
        """Test that hidden inputs are not flagged."""
        lens = AccessibilityLens()
        source = '<input type="hidden" name="csrf_token" value="abc123">'
        context = create_context(source)

        annotations = lens.analyze(context)

        form_annotations = [a for a in annotations if "form" in a.rule or "label" in a.rule]
        assert len(form_annotations) == 0

    def test_submit_button_not_flagged(self):
        """Test that submit buttons are not flagged for missing labels."""
        lens = AccessibilityLens()
        source = '<input type="submit" value="Submit">'
        context = create_context(source)

        annotations = lens.analyze(context)

        form_annotations = [a for a in annotations if a.rule == "missing_form_label"]
        assert len(form_annotations) == 0


class TestLensProperties:
    """Tests for lens basic properties."""

    def test_name(self):
        """Test lens name."""
        lens = AccessibilityLens()
        assert lens.name == "accessibility"

    def test_description(self):
        """Test lens description."""
        lens = AccessibilityLens()
        assert "accessibility" in lens.description.lower()

    def test_only_analyzes_supported_files(self):
        """Test that lens only analyzes HTML/JSX files."""
        lens = AccessibilityLens()
        source = '<img src="photo.jpg">'

        # Python file should not be analyzed
        from parallax.lang.python import PythonAnalyzer
        py_analyzer = PythonAnalyzer()
        py_source = 'print("hello")'
        py_ast = py_analyzer.parse_source(py_source, "test.py")

        lines = py_source.split("\n")
        diff_lines = tuple(
            DiffLine(kind=DiffLineKind.ADD, content=line, old_line=None, new_line=i + 1)
            for i, line in enumerate(lines)
        )
        hunk = DiffHunk(
            old_start=0, old_count=0, new_start=1, new_count=len(lines),
            lines=diff_lines, header="@@ -0,0 +1,%d @@" % len(lines)
        )
        file_diff = FileDiff(old_path=None, new_path="test.py", hunks=(hunk,), is_binary=False)
        parsed_diff = ParsedDiff(files=(file_diff,))

        context = AnalysisContext(diff=parsed_diff, files={"test.py": py_ast}, config=LensConfig())
        annotations = lens.analyze(context)

        assert len(annotations) == 0
