"""Lens base class and registry for Parallax."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from parallax.core.config import LensConfig
from parallax.core.types import Annotation
from parallax.diff.types import ParsedDiff
from parallax.lang.base import FileAST


@dataclass
class AnalysisContext:
    """Context passed to lenses for analysis.

    Contains all information needed to analyze code changes.
    """

    diff: ParsedDiff
    files: dict[str, FileAST]
    config: LensConfig

    def is_line_changed(self, path: str, line: int) -> bool:
        """Check if a line is in the diff (added/modified).

        Args:
            path: File path.
            line: 1-indexed line number.

        Returns:
            True if the line was added or modified in this diff.
        """
        return line in self.diff.changed_lines(path)

    def get_file(self, path: str) -> FileAST | None:
        """Get the FileAST for a path.

        Args:
            path: File path.

        Returns:
            FileAST if available, None otherwise.
        """
        return self.files.get(path)


class Lens(ABC):
    """Abstract base class for analysis lenses.

    A lens analyzes code changes through a specific concern
    (security, performance, etc.) and produces annotations.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this lens."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this lens checks."""
        pass

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> list[Annotation]:
        """Analyze code changes and return findings.

        Args:
            context: The analysis context with diff, ASTs, and config.

        Returns:
            List of annotations (findings) from this lens.
        """
        pass

    def configure(self, config: dict[str, Any]) -> None:
        """Accept lens-specific configuration.

        Override this method to handle custom configuration options.

        Args:
            config: Configuration dictionary from .parallax.yaml.
        """
        pass


class LensRegistry:
    """Registry of available lenses.

    Lenses register themselves using the @LensRegistry.register decorator.
    The registry provides access to all registered lenses by name.
    """

    _lenses: dict[str, type[Lens]] = {}

    @classmethod
    def register(cls, lens_class: type[Lens]) -> type[Lens]:
        """Register a lens class.

        Use as a decorator:
            @LensRegistry.register
            class MyLens(Lens):
                ...

        Args:
            lens_class: The lens class to register.

        Returns:
            The lens class (unchanged).
        """
        # Instantiate to get the name, then store the class
        instance = lens_class()
        cls._lenses[instance.name] = lens_class
        return lens_class

    @classmethod
    def get(cls, name: str) -> type[Lens] | None:
        """Get a lens class by name.

        Args:
            name: The lens name.

        Returns:
            The lens class, or None if not found.
        """
        return cls._lenses.get(name)

    @classmethod
    def all(cls) -> list[type[Lens]]:
        """Get all registered lens classes.

        Returns:
            List of all registered lens classes.
        """
        return list(cls._lenses.values())

    @classmethod
    def names(cls) -> list[str]:
        """Get all registered lens names.

        Returns:
            List of all registered lens names.
        """
        return list(cls._lenses.keys())

    @classmethod
    def clear(cls) -> None:
        """Clear all registered lenses.

        Primarily for testing.
        """
        cls._lenses.clear()
