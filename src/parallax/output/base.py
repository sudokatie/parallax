"""Base formatter interface for Parallax."""

from abc import ABC, abstractmethod

from parallax.core.types import AnalysisResult


class Formatter(ABC):
    """Abstract base class for output formatters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this formatter."""
        pass

    @abstractmethod
    def format(
        self,
        result: AnalysisResult,
        include_suggestions: bool = True,
    ) -> str:
        """Format analysis results.

        Args:
            result: The analysis result to format.
            include_suggestions: Whether to include fix suggestions.

        Returns:
            Formatted output as a string.
        """
        pass
