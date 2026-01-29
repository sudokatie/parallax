"""Configuration loading and validation for Parallax."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from parallax.core.types import Severity


class ConfigError(Exception):
    """Error in configuration."""

    pass


@dataclass
class LensConfig:
    """Configuration for a single lens."""

    enabled: bool = True
    severity_threshold: Severity = Severity.LOW
    rules: dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    """Full application configuration."""

    lenses: dict[str, LensConfig] = field(default_factory=dict)
    min_confidence: float = 0.5
    output_format: str = "text"
    fail_on: Optional[Severity] = None
    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: dict[str, list[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_config(self)

    def get_lens_config(self, lens_name: str) -> LensConfig:
        """Get config for a lens, returning defaults if not specified."""
        return self.lenses.get(lens_name, LensConfig())

    def is_lens_enabled(self, lens_name: str) -> bool:
        """Check if a lens is enabled."""
        return self.get_lens_config(lens_name).enabled


def validate_config(config: Config) -> None:
    """Validate configuration values.

    Raises:
        ConfigError: If any values are invalid.
    """
    if not 0.0 <= config.min_confidence <= 1.0:
        raise ConfigError(
            f"min_confidence must be between 0.0 and 1.0, got {config.min_confidence}"
        )

    valid_formats = {"text", "json", "sarif", "markdown"}
    if config.output_format not in valid_formats:
        raise ConfigError(
            f"output_format must be one of {valid_formats}, got {config.output_format}"
        )


def find_config_file(start_path: Optional[str] = None) -> Optional[str]:
    """Find .parallax.yaml in current directory or parents.

    Args:
        start_path: Starting directory (defaults to cwd).

    Returns:
        Path to config file if found, None otherwise.
    """
    if start_path:
        current = Path(start_path).resolve()
    else:
        current = Path.cwd()

    # Search up to filesystem root or git root
    while True:
        config_path = current / ".parallax.yaml"
        if config_path.exists():
            return str(config_path)

        # Check for .parallax.yml variant
        config_path_yml = current / ".parallax.yml"
        if config_path_yml.exists():
            return str(config_path_yml)

        # Stop at git root
        if (current / ".git").exists():
            break

        # Stop at filesystem root
        parent = current.parent
        if parent == current:
            break
        current = parent

    return None


def load_config(path: Optional[str] = None) -> Config:
    """Load configuration from file.

    Args:
        path: Path to config file. If None, searches for .parallax.yaml.

    Returns:
        Config object with loaded or default values.

    Raises:
        ConfigError: If the config file is invalid.
    """
    if path is None:
        path = find_config_file()

    if path is None:
        return Config()

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in config file: {e}") from e
    except OSError as e:
        raise ConfigError(f"Cannot read config file: {e}") from e

    if raw is None:
        return Config()

    return _parse_config(raw)


def _parse_config(raw: dict) -> Config:
    """Parse raw YAML dict into Config object."""
    lenses: dict[str, LensConfig] = {}

    # Parse lenses section
    if "lenses" in raw and isinstance(raw["lenses"], dict):
        for lens_name, lens_raw in raw["lenses"].items():
            if lens_raw is None:
                lens_raw = {}
            lenses[lens_name] = _parse_lens_config(lens_raw)

    # Parse settings section
    settings = raw.get("settings", {})
    if settings is None:
        settings = {}

    min_confidence = settings.get("min_confidence", 0.5)
    output_format = settings.get("output_format", "text")

    fail_on = None
    if "fail_on" in settings:
        try:
            fail_on = Severity(settings["fail_on"])
        except ValueError:
            raise ConfigError(f"Invalid severity for fail_on: {settings['fail_on']}")

    # Parse ignore section
    ignore = raw.get("ignore", {})
    if ignore is None:
        ignore = {}

    ignore_paths = ignore.get("paths", [])
    if ignore_paths is None:
        ignore_paths = []

    ignore_rules = ignore.get("rules", {})
    if ignore_rules is None:
        ignore_rules = {}

    # Convert ignore_rules list format to dict format if needed
    if isinstance(ignore_rules, list):
        # Format: ["security/sql_injection:tests/*", ...]
        parsed_rules: dict[str, list[str]] = {}
        for rule_pattern in ignore_rules:
            if ":" in rule_pattern:
                rule, pattern = rule_pattern.split(":", 1)
                if rule not in parsed_rules:
                    parsed_rules[rule] = []
                parsed_rules[rule].append(pattern)
            else:
                # No pattern means ignore everywhere
                if rule_pattern not in parsed_rules:
                    parsed_rules[rule_pattern] = []
                parsed_rules[rule_pattern].append("*")
        ignore_rules = parsed_rules

    return Config(
        lenses=lenses,
        min_confidence=min_confidence,
        output_format=output_format,
        fail_on=fail_on,
        ignore_paths=ignore_paths,
        ignore_rules=ignore_rules,
    )


def _parse_lens_config(raw: dict) -> LensConfig:
    """Parse lens configuration."""
    enabled = raw.get("enabled", True)

    severity_threshold = Severity.LOW
    if "severity_threshold" in raw:
        try:
            severity_threshold = Severity(raw["severity_threshold"])
        except ValueError:
            raise ConfigError(f"Invalid severity_threshold: {raw['severity_threshold']}")

    rules = raw.get("rules", {})
    if rules is None:
        rules = {}

    return LensConfig(enabled=enabled, severity_threshold=severity_threshold, rules=rules)


def merge_cli_args(config: Config, **kwargs: Any) -> Config:
    """Merge CLI arguments into configuration.

    CLI args take precedence over config file values.

    Args:
        config: Base configuration.
        **kwargs: CLI arguments (lenses, output_format, min_confidence, etc.)

    Returns:
        New Config with merged values.
    """
    lenses = dict(config.lenses)
    min_confidence = config.min_confidence
    output_format = config.output_format
    fail_on = config.fail_on
    ignore_paths = list(config.ignore_paths)
    ignore_rules = dict(config.ignore_rules)

    # Override with CLI args if provided
    if kwargs.get("min_confidence") is not None:
        min_confidence = kwargs["min_confidence"]

    if kwargs.get("output_format") is not None:
        output_format = kwargs["output_format"]

    if kwargs.get("fail_on") is not None:
        fail_on = kwargs["fail_on"]

    # Handle lens enable/disable from CLI
    if kwargs.get("enable_lenses"):
        for lens_name in kwargs["enable_lenses"]:
            if lens_name not in lenses:
                lenses[lens_name] = LensConfig()
            lenses[lens_name] = LensConfig(
                enabled=True,
                severity_threshold=lenses[lens_name].severity_threshold,
                rules=lenses[lens_name].rules,
            )

    if kwargs.get("disable_lenses"):
        for lens_name in kwargs["disable_lenses"]:
            if lens_name not in lenses:
                lenses[lens_name] = LensConfig(enabled=False)
            else:
                lenses[lens_name] = LensConfig(
                    enabled=False,
                    severity_threshold=lenses[lens_name].severity_threshold,
                    rules=lenses[lens_name].rules,
                )

    return Config(
        lenses=lenses,
        min_confidence=min_confidence,
        output_format=output_format,
        fail_on=fail_on,
        ignore_paths=ignore_paths,
        ignore_rules=ignore_rules,
    )
