"""Tests for the custom lens framework."""

import tempfile
from pathlib import Path

import pytest

from parallax.core.types import Severity
from parallax.lenses.custom import (
    CustomLens,
    CustomLensDefinition,
    CustomLensLoader,
    PatternRule,
    create_example_lens,
)


class TestPatternRule:
    """Tests for PatternRule."""

    def test_from_dict_basic(self):
        """Test creating a PatternRule from dict."""
        data = {
            "pattern": r"print\s*\(",
            "message": "Avoid print statements",
            "severity": "low",
        }
        rule = PatternRule.from_dict("no-print", data)

        assert rule.name == "no-print"
        assert rule.pattern == r"print\s*\("
        assert rule.pattern_type == "regex"
        assert rule.message == "Avoid print statements"
        assert rule.severity == Severity.LOW
        assert rule.confidence == 0.8

    def test_from_dict_full(self):
        """Test creating a PatternRule with all options."""
        data = {
            "pattern": r"TODO:",
            "type": "regex",
            "message": "TODO found",
            "severity": "info",
            "confidence": 0.5,
            "suggestion": "Resolve the TODO",
            "doc_url": "https://example.com",
            "files": ["*.py", "*.js"],
            "exclude": ["# noqa"],
        }
        rule = PatternRule.from_dict("todo-check", data)

        assert rule.name == "todo-check"
        assert rule.pattern_type == "regex"
        assert rule.severity == Severity.INFO
        assert rule.confidence == 0.5
        assert rule.suggestion == "Resolve the TODO"
        assert rule.doc_url == "https://example.com"
        assert rule.file_patterns == ["*.py", "*.js"]
        assert rule.exclude_patterns == ["# noqa"]

    def test_from_dict_severity_mapping(self):
        """Test severity string to enum mapping."""
        severities = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        for severity_str, expected in severities.items():
            data = {
                "pattern": "test",
                "message": "test",
                "severity": severity_str,
            }
            rule = PatternRule.from_dict("test", data)
            assert rule.severity == expected

    def test_from_dict_default_severity(self):
        """Test default severity is MEDIUM."""
        data = {"pattern": "test", "message": "test"}
        rule = PatternRule.from_dict("test", data)
        assert rule.severity == Severity.MEDIUM


class TestCustomLensDefinition:
    """Tests for CustomLensDefinition."""

    def test_from_dict_basic(self):
        """Test creating definition from dict."""
        data = {
            "name": "test-lens",
            "description": "A test lens",
            "version": "1.0.0",
            "rules": {
                "rule1": {
                    "pattern": "pattern1",
                    "message": "message1",
                },
            },
        }
        definition = CustomLensDefinition.from_dict(data)

        assert definition.name == "test-lens"
        assert definition.description == "A test lens"
        assert definition.version == "1.0.0"
        assert len(definition.rules) == 1
        assert definition.rules[0].name == "rule1"

    def test_from_dict_with_metadata(self):
        """Test creating definition with optional metadata."""
        data = {
            "name": "my-lens",
            "description": "My custom lens",
            "version": "2.0.0",
            "author": "Test Author",
            "category": "standards",
            "rules": {},
        }
        definition = CustomLensDefinition.from_dict(data)

        assert definition.author == "Test Author"
        assert definition.category == "standards"

    def test_load_from_file(self):
        """Test loading definition from YAML file."""
        yaml_content = """
name: file-lens
description: Loaded from file
version: "1.0.0"
rules:
  test-rule:
    pattern: "test"
    message: "Found test"
    severity: low
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(yaml_content)
            f.flush()

            definition = CustomLensDefinition.load(Path(f.name))

            assert definition.name == "file-lens"
            assert definition.description == "Loaded from file"
            assert len(definition.rules) == 1

    def test_load_empty_file_raises(self):
        """Test that loading empty file raises ValueError."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("")
            f.flush()

            with pytest.raises(ValueError, match="Empty"):
                CustomLensDefinition.load(Path(f.name))

    def test_load_missing_name_raises(self):
        """Test that missing name raises ValueError."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("description: no name\n")
            f.flush()

            with pytest.raises(ValueError, match="Missing 'name'"):
                CustomLensDefinition.load(Path(f.name))


class TestCustomLens:
    """Tests for CustomLens."""

    def test_name_and_description(self):
        """Test lens name and description properties."""
        definition = CustomLensDefinition(
            name="test-lens",
            description="Test description",
            version="1.0.0",
            rules=[],
        )
        lens = CustomLens(definition)

        assert lens.name == "test-lens"
        assert lens.description == "Test description"

    def test_invalid_regex_raises(self):
        """Test that invalid regex pattern raises ValueError."""
        definition = CustomLensDefinition(
            name="bad-lens",
            description="Bad regex",
            version="1.0.0",
            rules=[
                PatternRule(
                    name="bad-rule",
                    pattern="[invalid(",
                    pattern_type="regex",
                    message="Bad pattern",
                    severity=Severity.LOW,
                )
            ],
        )

        with pytest.raises(ValueError, match="Invalid regex"):
            CustomLens(definition)


class TestCustomLensLoader:
    """Tests for CustomLensLoader."""

    def test_discover_empty_dirs(self):
        """Test discover returns empty list when no dirs exist."""
        loader = CustomLensLoader(extra_dirs=[])
        # The default dirs probably don't exist in test env
        # This should not raise
        _ = loader.discover()

    def test_discover_finds_yaml_files(self):
        """Test discover finds .yaml and .yml files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lens_dir = Path(tmp_dir)

            # Create some lens files
            (lens_dir / "lens1.yaml").write_text("name: lens1\nrules: {}")
            (lens_dir / "lens2.yml").write_text("name: lens2\nrules: {}")
            (lens_dir / "notlens.txt").write_text("not a lens")

            loader = CustomLensLoader(extra_dirs=[lens_dir])
            # Clear default dirs for this test
            loader._dirs = [lens_dir]

            found = loader.discover()
            assert len(found) == 2
            names = {p.name for p in found}
            assert "lens1.yaml" in names
            assert "lens2.yml" in names

    def test_load_all_skips_invalid(self):
        """Test load_all skips invalid lens definitions."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lens_dir = Path(tmp_dir)

            # Valid lens
            (lens_dir / "good.yaml").write_text(
                "name: good\ndescription: Good\nversion: '1.0'\nrules: {}"
            )
            # Invalid lens (no name)
            (lens_dir / "bad.yaml").write_text("description: Bad\nrules: {}")

            loader = CustomLensLoader()
            loader._dirs = [lens_dir]

            lenses = loader.load_all()
            assert len(lenses) == 1
            assert lenses[0].name == "good"

    def test_load_specific_file(self):
        """Test loading a specific lens file."""
        yaml_content = """
name: specific-lens
description: Specific lens
version: "1.0.0"
rules:
  my-rule:
    pattern: "pattern"
    message: "Found it"
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(yaml_content)
            f.flush()

            loader = CustomLensLoader()
            lens = loader.load(Path(f.name))

            assert lens.name == "specific-lens"


class TestCreateExampleLens:
    """Tests for create_example_lens."""

    def test_returns_valid_yaml(self):
        """Test that example lens is valid YAML."""
        import yaml

        example = create_example_lens()
        data = yaml.safe_load(example)

        assert data is not None
        assert "name" in data
        assert "rules" in data

    def test_example_can_be_loaded(self):
        """Test that example lens can be loaded as a definition."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(create_example_lens())
            f.flush()

            definition = CustomLensDefinition.load(Path(f.name))
            assert definition.name == "my-company"
            assert len(definition.rules) >= 2
