"""Tests for configuration module."""

import tempfile
from pathlib import Path

import pytest

from parallax.core.config import (
    Config,
    ConfigError,
    LensConfig,
    find_config_file,
    load_config,
    merge_cli_args,
)
from parallax.core.types import Severity


class TestLensConfig:
    """Tests for LensConfig."""

    def test_default_values(self):
        """Test default lens config values."""
        config = LensConfig()
        assert config.enabled is True
        assert config.severity_threshold == Severity.LOW
        assert config.rules == {}

    def test_custom_values(self):
        """Test custom lens config values."""
        config = LensConfig(
            enabled=False,
            severity_threshold=Severity.HIGH,
            rules={"sql_injection": True, "xss": False},
        )
        assert config.enabled is False
        assert config.severity_threshold == Severity.HIGH
        assert config.rules["sql_injection"] is True


class TestConfig:
    """Tests for Config."""

    def test_default_values(self):
        """Test default config values."""
        config = Config()
        assert config.min_confidence == 0.5
        assert config.output_format == "text"
        assert config.fail_on is None
        assert config.ignore_paths == []
        assert config.ignore_rules == {}

    def test_get_lens_config_existing(self):
        """Test getting existing lens config."""
        lens_config = LensConfig(enabled=False)
        config = Config(lenses={"security": lens_config})
        assert config.get_lens_config("security") == lens_config

    def test_get_lens_config_missing(self):
        """Test getting missing lens config returns defaults."""
        config = Config()
        lens_config = config.get_lens_config("nonexistent")
        assert lens_config.enabled is True
        assert lens_config.severity_threshold == Severity.LOW

    def test_is_lens_enabled_true(self):
        """Test checking enabled lens."""
        config = Config(lenses={"security": LensConfig(enabled=True)})
        assert config.is_lens_enabled("security") is True

    def test_is_lens_enabled_false(self):
        """Test checking disabled lens."""
        config = Config(lenses={"security": LensConfig(enabled=False)})
        assert config.is_lens_enabled("security") is False

    def test_is_lens_enabled_missing(self):
        """Test checking unlisted lens (defaults to enabled)."""
        config = Config()
        assert config.is_lens_enabled("security") is True


class TestValidation:
    """Tests for configuration validation."""

    def test_invalid_min_confidence_negative(self):
        """Test that negative confidence raises error."""
        with pytest.raises(ConfigError, match="min_confidence"):
            Config(min_confidence=-0.1)

    def test_invalid_min_confidence_too_high(self):
        """Test that confidence > 1 raises error."""
        with pytest.raises(ConfigError, match="min_confidence"):
            Config(min_confidence=1.5)

    def test_valid_min_confidence_boundary(self):
        """Test boundary values for confidence."""
        config0 = Config(min_confidence=0.0)
        config1 = Config(min_confidence=1.0)
        assert config0.min_confidence == 0.0
        assert config1.min_confidence == 1.0

    def test_invalid_output_format(self):
        """Test that invalid output format raises error."""
        with pytest.raises(ConfigError, match="output_format"):
            Config(output_format="invalid")

    def test_valid_output_formats(self):
        """Test all valid output formats."""
        for fmt in ["text", "json", "sarif", "markdown"]:
            config = Config(output_format=fmt)
            assert config.output_format == fmt


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_missing_file_returns_defaults(self):
        """Test that missing config file returns defaults when no path given."""
        # When path is None and no config file exists, return defaults
        with tempfile.TemporaryDirectory() as tmpdir:
            import os
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                config = load_config(None)
                assert config.min_confidence == 0.5
            finally:
                os.chdir(old_cwd)

    def test_load_valid_yaml(self):
        """Test loading valid YAML config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
lenses:
  security:
    enabled: true
    rules:
      sql_injection: true
  performance:
    enabled: false

settings:
  min_confidence: 0.7
  output_format: json
  fail_on: high

ignore:
  paths:
    - "**/test_*.py"
    - "**/migrations/**"
""")
            f.flush()
            config = load_config(f.name)

        assert config.min_confidence == 0.7
        assert config.output_format == "json"
        assert config.fail_on == Severity.HIGH
        assert config.is_lens_enabled("security") is True
        assert config.is_lens_enabled("performance") is False
        assert "**/test_*.py" in config.ignore_paths

    def test_load_empty_yaml(self):
        """Test loading empty YAML returns defaults."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            f.flush()
            config = load_config(f.name)

        assert config.min_confidence == 0.5
        assert config.output_format == "text"

    def test_load_invalid_yaml(self):
        """Test that invalid YAML raises ConfigError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: {{{")
            f.flush()
            with pytest.raises(ConfigError, match="Invalid YAML"):
                load_config(f.name)

    def test_load_no_path_returns_defaults(self):
        """Test that load_config with no path and no file returns defaults."""
        # This test runs from a directory without .parallax.yaml
        config = load_config(None)
        assert config.min_confidence == 0.5

    def test_load_invalid_severity(self):
        """Test that invalid severity value raises error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
settings:
  fail_on: invalid_severity
""")
            f.flush()
            with pytest.raises(ConfigError, match="Invalid severity"):
                load_config(f.name)


class TestFindConfigFile:
    """Tests for find_config_file function."""

    def test_find_in_current_dir(self):
        """Test finding config in current directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".parallax.yaml"
            config_path.write_text("lenses: {}")
            found = find_config_file(tmpdir)
            # Resolve both paths to handle macOS /var -> /private/var symlink
            assert Path(found).resolve() == config_path.resolve()

    def test_find_yml_variant(self):
        """Test finding .parallax.yml variant."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".parallax.yml"
            config_path.write_text("lenses: {}")
            found = find_config_file(tmpdir)
            # Resolve both paths to handle macOS /var -> /private/var symlink
            assert Path(found).resolve() == config_path.resolve()

    def test_find_in_parent_dir(self):
        """Test finding config in parent directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create config in parent
            config_path = Path(tmpdir) / ".parallax.yaml"
            config_path.write_text("lenses: {}")

            # Create child directory
            child_dir = Path(tmpdir) / "child" / "grandchild"
            child_dir.mkdir(parents=True)

            found = find_config_file(str(child_dir))
            # Resolve both paths to handle macOS /var -> /private/var symlink
            assert Path(found).resolve() == config_path.resolve()

    def test_find_none_when_missing(self):
        """Test returns None when no config found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            found = find_config_file(tmpdir)
            assert found is None


class TestMergeCliArgs:
    """Tests for merge_cli_args function."""

    def test_merge_min_confidence(self):
        """Test merging min_confidence from CLI."""
        config = Config(min_confidence=0.5)
        merged = merge_cli_args(config, min_confidence=0.8)
        assert merged.min_confidence == 0.8

    def test_merge_output_format(self):
        """Test merging output_format from CLI."""
        config = Config(output_format="text")
        merged = merge_cli_args(config, output_format="json")
        assert merged.output_format == "json"

    def test_merge_fail_on(self):
        """Test merging fail_on from CLI."""
        config = Config(fail_on=None)
        merged = merge_cli_args(config, fail_on=Severity.HIGH)
        assert merged.fail_on == Severity.HIGH

    def test_merge_enable_lenses(self):
        """Test enabling lenses from CLI."""
        config = Config(lenses={"security": LensConfig(enabled=False)})
        merged = merge_cli_args(config, enable_lenses=["security"])
        assert merged.is_lens_enabled("security") is True

    def test_merge_disable_lenses(self):
        """Test disabling lenses from CLI."""
        config = Config(lenses={"security": LensConfig(enabled=True)})
        merged = merge_cli_args(config, disable_lenses=["security"])
        assert merged.is_lens_enabled("security") is False

    def test_merge_preserves_unspecified(self):
        """Test that unspecified args preserve original values."""
        config = Config(min_confidence=0.7, output_format="json")
        merged = merge_cli_args(config)
        assert merged.min_confidence == 0.7
        assert merged.output_format == "json"

    def test_merge_none_values_ignored(self):
        """Test that None CLI values are ignored."""
        config = Config(min_confidence=0.7)
        merged = merge_cli_args(config, min_confidence=None)
        assert merged.min_confidence == 0.7


class TestIgnoreRulesParsing:
    """Tests for ignore rules parsing."""

    def test_parse_ignore_rules_list_format(self):
        """Test parsing ignore rules in list format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
ignore:
  rules:
    - security/sql_injection:tests/*
    - maintainability/complexity:generated/*
""")
            f.flush()
            config = load_config(f.name)

        assert "security/sql_injection" in config.ignore_rules
        assert "tests/*" in config.ignore_rules["security/sql_injection"]

    def test_parse_ignore_rules_dict_format(self):
        """Test parsing ignore rules in dict format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
ignore:
  rules:
    security/sql_injection:
      - tests/*
      - fixtures/*
""")
            f.flush()
            config = load_config(f.name)

        assert "security/sql_injection" in config.ignore_rules
        assert "tests/*" in config.ignore_rules["security/sql_injection"]
