"""Core module for Parallax."""

from parallax.core.config import (
    Config,
    ConfigError,
    LensConfig,
    find_config_file,
    load_config,
    merge_cli_args,
)
from parallax.core.types import AnalysisResult, Annotation, Location, Severity

__all__ = [
    "Severity",
    "Location",
    "Annotation",
    "AnalysisResult",
    "Config",
    "ConfigError",
    "LensConfig",
    "load_config",
    "find_config_file",
    "merge_cli_args",
]
