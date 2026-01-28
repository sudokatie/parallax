"""Tests for core types."""

import pytest

from parallax.core.types import AnalysisResult, Annotation, Location, Severity


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Verify severity values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_comparison_less_than(self):
        """Verify severity comparison operators."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_severity_comparison_greater_than(self):
        """Verify greater than comparison."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_severity_comparison_equal(self):
        """Verify equality and less/greater or equal."""
        assert Severity.HIGH <= Severity.HIGH
        assert Severity.HIGH >= Severity.HIGH
        assert not Severity.HIGH < Severity.HIGH
        assert not Severity.HIGH > Severity.HIGH

    def test_severity_comparison_le_ge(self):
        """Verify less/greater or equal across levels."""
        assert Severity.LOW <= Severity.MEDIUM
        assert Severity.MEDIUM >= Severity.LOW


class TestLocation:
    """Tests for Location dataclass."""

    def test_location_creation(self):
        """Test basic location creation."""
        loc = Location(file="test.py", start_line=10, end_line=15)
        assert loc.file == "test.py"
        assert loc.start_line == 10
        assert loc.end_line == 15
        assert loc.start_column is None
        assert loc.end_column is None

    def test_location_with_columns(self):
        """Test location with column info."""
        loc = Location(
            file="test.py", start_line=10, end_line=10, start_column=5, end_column=20
        )
        assert loc.start_column == 5
        assert loc.end_column == 20

    def test_location_str_without_column(self):
        """Test string representation without column."""
        loc = Location(file="test.py", start_line=42, end_line=42)
        assert str(loc) == "test.py:42"

    def test_location_str_with_column(self):
        """Test string representation with column."""
        loc = Location(file="test.py", start_line=42, end_line=42, start_column=10)
        assert str(loc) == "test.py:42:10"

    def test_location_is_frozen(self):
        """Verify location is immutable."""
        loc = Location(file="test.py", start_line=10, end_line=15)
        with pytest.raises(AttributeError):
            loc.file = "other.py"

    def test_location_equality(self):
        """Test location equality."""
        loc1 = Location(file="test.py", start_line=10, end_line=15)
        loc2 = Location(file="test.py", start_line=10, end_line=15)
        loc3 = Location(file="test.py", start_line=10, end_line=20)
        assert loc1 == loc2
        assert loc1 != loc3

    def test_location_hashable(self):
        """Verify locations can be used in sets."""
        loc1 = Location(file="test.py", start_line=10, end_line=15)
        loc2 = Location(file="test.py", start_line=10, end_line=15)
        s = {loc1, loc2}
        assert len(s) == 1


class TestAnnotation:
    """Tests for Annotation dataclass."""

    def test_annotation_creation(self):
        """Test basic annotation creation."""
        loc = Location(file="test.py", start_line=10, end_line=10)
        ann = Annotation(
            lens="security",
            rule="sql_injection",
            location=loc,
            severity=Severity.HIGH,
            confidence=0.9,
            message="SQL injection risk",
        )
        assert ann.lens == "security"
        assert ann.rule == "sql_injection"
        assert ann.severity == Severity.HIGH
        assert ann.confidence == 0.9
        assert ann.suggestion is None

    def test_annotation_with_optional_fields(self):
        """Test annotation with all optional fields."""
        loc = Location(file="test.py", start_line=10, end_line=10)
        ann = Annotation(
            lens="security",
            rule="sql_injection",
            location=loc,
            severity=Severity.HIGH,
            confidence=0.9,
            message="SQL injection risk",
            suggestion="Use parameterized queries",
            doc_url="https://example.com/docs",
            category="injection",
        )
        assert ann.suggestion == "Use parameterized queries"
        assert ann.doc_url == "https://example.com/docs"
        assert ann.category == "injection"

    def test_annotation_confidence_validation_low(self):
        """Test confidence below 0 raises error."""
        loc = Location(file="test.py", start_line=10, end_line=10)
        with pytest.raises(ValueError, match="Confidence must be between"):
            Annotation(
                lens="test",
                rule="test",
                location=loc,
                severity=Severity.LOW,
                confidence=-0.1,
                message="test",
            )

    def test_annotation_confidence_validation_high(self):
        """Test confidence above 1 raises error."""
        loc = Location(file="test.py", start_line=10, end_line=10)
        with pytest.raises(ValueError, match="Confidence must be between"):
            Annotation(
                lens="test",
                rule="test",
                location=loc,
                severity=Severity.LOW,
                confidence=1.1,
                message="test",
            )

    def test_annotation_confidence_boundary_values(self):
        """Test confidence at boundary values (0 and 1)."""
        loc = Location(file="test.py", start_line=10, end_line=10)
        ann0 = Annotation(
            lens="test",
            rule="test",
            location=loc,
            severity=Severity.LOW,
            confidence=0.0,
            message="test",
        )
        ann1 = Annotation(
            lens="test",
            rule="test",
            location=loc,
            severity=Severity.LOW,
            confidence=1.0,
            message="test",
        )
        assert ann0.confidence == 0.0
        assert ann1.confidence == 1.0

    def test_annotation_to_dict(self):
        """Test annotation serialization to dict."""
        loc = Location(file="test.py", start_line=10, end_line=15, start_column=5, end_column=20)
        ann = Annotation(
            lens="security",
            rule="sql_injection",
            location=loc,
            severity=Severity.HIGH,
            confidence=0.9,
            message="SQL injection risk",
            suggestion="Use params",
        )
        d = ann.to_dict()
        assert d["lens"] == "security"
        assert d["rule"] == "sql_injection"
        assert d["severity"] == "high"
        assert d["confidence"] == 0.9
        assert d["message"] == "SQL injection risk"
        assert d["suggestion"] == "Use params"
        assert d["location"]["file"] == "test.py"
        assert d["location"]["start_line"] == 10
        assert d["location"]["end_line"] == 15
        assert d["location"]["start_column"] == 5
        assert d["location"]["end_column"] == 20


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""

    def test_analysis_result_empty(self):
        """Test empty analysis result."""
        result = AnalysisResult(target="test.patch")
        assert result.target == "test.patch"
        assert result.annotations == []
        assert result.errors == []

    def test_analysis_result_summary_empty(self):
        """Test summary with no annotations."""
        result = AnalysisResult(target="test.patch")
        summary = result.summary
        assert summary["total"] == 0
        assert summary["by_severity"] == {}
        assert summary["by_lens"] == {}

    def test_analysis_result_summary_with_annotations(self):
        """Test summary calculation with annotations."""
        loc = Location(file="test.py", start_line=10, end_line=10)
        annotations = [
            Annotation(
                lens="security",
                rule="sql_injection",
                location=loc,
                severity=Severity.HIGH,
                confidence=0.9,
                message="test",
            ),
            Annotation(
                lens="security",
                rule="xss",
                location=loc,
                severity=Severity.HIGH,
                confidence=0.8,
                message="test",
            ),
            Annotation(
                lens="maintainability",
                rule="complexity",
                location=loc,
                severity=Severity.MEDIUM,
                confidence=1.0,
                message="test",
            ),
        ]
        result = AnalysisResult(target="test.patch", annotations=annotations)
        summary = result.summary
        assert summary["total"] == 3
        assert summary["by_severity"] == {"high": 2, "medium": 1}
        assert summary["by_lens"] == {"security": 2, "maintainability": 1}

    def test_analysis_result_with_errors(self):
        """Test result with errors."""
        result = AnalysisResult(
            target="test.patch", errors=["Failed to parse file.py", "Unknown lens: foo"]
        )
        assert len(result.errors) == 2
        assert "Failed to parse" in result.errors[0]
