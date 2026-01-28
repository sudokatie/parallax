"""Tests for output formatters."""

import json

import pytest

from parallax.core.types import AnalysisResult, Annotation, Location, Severity
from parallax.output import get_formatter
from parallax.output.json import JSONFormatter
from parallax.output.markdown import MarkdownFormatter
from parallax.output.sarif import SARIFFormatter
from parallax.output.text import TextFormatter


@pytest.fixture
def sample_annotations() -> list[Annotation]:
    """Create sample annotations for testing."""
    return [
        Annotation(
            lens="security",
            rule="sql_injection",
            location=Location(
                file="src/db.py",
                start_line=45,
                end_line=45,
            ),
            severity=Severity.HIGH,
            confidence=0.9,
            message="SQL injection risk detected",
            suggestion="Use parameterized queries",
            category="injection",
        ),
        Annotation(
            lens="maintainability",
            rule="cyclomatic_complexity",
            location=Location(
                file="src/handler.py",
                start_line=23,
                end_line=50,
            ),
            severity=Severity.MEDIUM,
            confidence=0.85,
            message="Function has high complexity",
            suggestion="Break into smaller functions",
        ),
    ]


@pytest.fixture
def sample_result(sample_annotations: list[Annotation]) -> AnalysisResult:
    """Create a sample analysis result."""
    return AnalysisResult(
        target="test.patch",
        annotations=sample_annotations,
    )


@pytest.fixture
def empty_result() -> AnalysisResult:
    """Create an empty analysis result."""
    return AnalysisResult(target="clean.patch")


class TestTextFormatter:
    """Tests for TextFormatter."""

    def test_format_with_findings(self, sample_result: AnalysisResult) -> None:
        """Test formatting results with findings."""
        formatter = TextFormatter()
        output = formatter.format(sample_result)

        assert "Parallax Analysis" in output
        assert "test.patch" in output
        assert "2 finding(s)" in output
        assert "security/sql_injection" in output
        assert "maintainability/cyclomatic_complexity" in output
        assert "SQL injection risk" in output
        assert "HIGH" in output
        assert "MEDIUM" in output

    def test_format_empty_result(self, empty_result: AnalysisResult) -> None:
        """Test formatting empty results."""
        formatter = TextFormatter()
        output = formatter.format(empty_result)

        assert "No findings" in output

    def test_suggestions_included_by_default(self, sample_result: AnalysisResult) -> None:
        """Test that suggestions are included by default."""
        formatter = TextFormatter()
        output = formatter.format(sample_result)

        assert "Suggestion:" in output
        assert "parameterized queries" in output

    def test_suggestions_can_be_omitted(self, sample_result: AnalysisResult) -> None:
        """Test that suggestions can be omitted."""
        formatter = TextFormatter()
        output = formatter.format(sample_result, include_suggestions=False)

        assert "Suggestion:" not in output

    def test_errors_displayed(self, sample_result: AnalysisResult) -> None:
        """Test that errors are displayed when there are findings."""
        result = AnalysisResult(
            target="test.patch",
            annotations=sample_result.annotations,
            errors=["Lens 'performance' failed: timeout"],
        )
        formatter = TextFormatter()
        output = formatter.format(result)

        assert "Errors:" in output
        assert "performance" in output


class TestJSONFormatter:
    """Tests for JSONFormatter."""

    def test_format_produces_valid_json(self, sample_result: AnalysisResult) -> None:
        """Test that output is valid JSON."""
        formatter = JSONFormatter()
        output = formatter.format(sample_result)

        data = json.loads(output)
        assert "version" in data
        assert "target" in data
        assert "summary" in data
        assert "annotations" in data

    def test_summary_counts(self, sample_result: AnalysisResult) -> None:
        """Test that summary contains correct counts."""
        formatter = JSONFormatter()
        output = formatter.format(sample_result)

        data = json.loads(output)
        assert data["summary"]["total"] == 2
        assert data["summary"]["by_severity"]["high"] == 1
        assert data["summary"]["by_severity"]["medium"] == 1

    def test_annotation_structure(self, sample_result: AnalysisResult) -> None:
        """Test annotation structure in JSON output."""
        formatter = JSONFormatter()
        output = formatter.format(sample_result)

        data = json.loads(output)
        annotation = data["annotations"][0]

        assert annotation["lens"] == "security"
        assert annotation["rule"] == "sql_injection"
        assert annotation["location"]["file"] == "src/db.py"
        assert annotation["severity"] == "high"
        assert annotation["confidence"] == 0.9

    def test_empty_result(self, empty_result: AnalysisResult) -> None:
        """Test empty result produces valid JSON."""
        formatter = JSONFormatter()
        output = formatter.format(empty_result)

        data = json.loads(output)
        assert data["summary"]["total"] == 0
        assert data["annotations"] == []


class TestSARIFFormatter:
    """Tests for SARIFFormatter."""

    def test_sarif_schema_compliance(self, sample_result: AnalysisResult) -> None:
        """Test that output follows SARIF schema."""
        formatter = SARIFFormatter()
        output = formatter.format(sample_result)

        data = json.loads(output)
        assert data["$schema"].endswith("sarif-schema-2.1.0.json")
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_tool_info(self, sample_result: AnalysisResult) -> None:
        """Test tool information in SARIF output."""
        formatter = SARIFFormatter()
        output = formatter.format(sample_result)

        data = json.loads(output)
        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "Parallax"
        assert "version" in tool
        assert "rules" in tool

    def test_results_structure(self, sample_result: AnalysisResult) -> None:
        """Test results structure in SARIF output."""
        formatter = SARIFFormatter()
        output = formatter.format(sample_result)

        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 2

        result = results[0]
        assert result["ruleId"] == "security/sql_injection"
        assert result["level"] == "error"  # HIGH maps to error
        assert "message" in result
        assert "locations" in result

    def test_severity_mapping(self, sample_result: AnalysisResult) -> None:
        """Test severity to SARIF level mapping."""
        formatter = SARIFFormatter()
        output = formatter.format(sample_result)

        data = json.loads(output)
        results = data["runs"][0]["results"]

        # HIGH -> error
        high_result = next(r for r in results if "sql_injection" in r["ruleId"])
        assert high_result["level"] == "error"

        # MEDIUM -> warning
        medium_result = next(r for r in results if "complexity" in r["ruleId"])
        assert medium_result["level"] == "warning"


class TestMarkdownFormatter:
    """Tests for MarkdownFormatter."""

    def test_header(self, sample_result: AnalysisResult) -> None:
        """Test markdown header."""
        formatter = MarkdownFormatter()
        output = formatter.format(sample_result)

        assert "# Parallax Analysis" in output
        assert "test.patch" in output

    def test_summary_section(self, sample_result: AnalysisResult) -> None:
        """Test summary section."""
        formatter = MarkdownFormatter()
        output = formatter.format(sample_result)

        # The formatter shows finding count in header
        assert "2 finding" in output
        assert "test.patch" in output

    def test_findings_by_lens(self, sample_result: AnalysisResult) -> None:
        """Test findings grouped by lens."""
        formatter = MarkdownFormatter()
        output = formatter.format(sample_result)

        assert "### Security" in output or "### security" in output.lower()
        assert "### Maintainability" in output or "### maintainability" in output.lower()

    def test_table_format(self, sample_result: AnalysisResult) -> None:
        """Test that findings are in table format."""
        formatter = MarkdownFormatter()
        output = formatter.format(sample_result)

        assert "|" in output  # Table separator
        assert "Severity" in output or "severity" in output.lower()
        assert "Location" in output or "location" in output.lower()

    def test_empty_result(self, empty_result: AnalysisResult) -> None:
        """Test empty result."""
        formatter = MarkdownFormatter()
        output = formatter.format(empty_result)

        assert "No findings" in output or "0" in output


class TestGetFormatter:
    """Tests for get_formatter factory function."""

    def test_get_text_formatter(self) -> None:
        """Test getting text formatter."""
        formatter = get_formatter("text")
        assert isinstance(formatter, TextFormatter)

    def test_get_json_formatter(self) -> None:
        """Test getting JSON formatter."""
        formatter = get_formatter("json")
        assert isinstance(formatter, JSONFormatter)

    def test_get_sarif_formatter(self) -> None:
        """Test getting SARIF formatter."""
        formatter = get_formatter("sarif")
        assert isinstance(formatter, SARIFFormatter)

    def test_get_markdown_formatter(self) -> None:
        """Test getting markdown formatter."""
        formatter = get_formatter("markdown")
        assert isinstance(formatter, MarkdownFormatter)

    def test_invalid_format_raises(self) -> None:
        """Test that invalid format raises error."""
        with pytest.raises((ValueError, KeyError)):
            get_formatter("invalid")
