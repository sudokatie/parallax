"""Core data types for Parallax."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Severity levels for annotations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return not self < other


@dataclass(frozen=True)
class Location:
    """Location of a finding in source code."""

    file: str
    start_line: int
    end_line: int
    start_column: Optional[int] = None
    end_column: Optional[int] = None

    def __str__(self) -> str:
        if self.start_column is not None:
            return f"{self.file}:{self.start_line}:{self.start_column}"
        return f"{self.file}:{self.start_line}"


@dataclass(frozen=True)
class Annotation:
    """A single finding from a lens."""

    lens: str
    rule: str
    location: Location
    severity: Severity
    confidence: float
    message: str
    suggestion: Optional[str] = None
    doc_url: Optional[str] = None
    category: Optional[str] = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")

    def to_dict(self) -> dict:
        """Convert annotation to dictionary."""
        return {
            "lens": self.lens,
            "rule": self.rule,
            "location": {
                "file": self.location.file,
                "start_line": self.location.start_line,
                "end_line": self.location.end_line,
                "start_column": self.location.start_column,
                "end_column": self.location.end_column,
            },
            "severity": self.severity.value,
            "confidence": self.confidence,
            "message": self.message,
            "suggestion": self.suggestion,
            "doc_url": self.doc_url,
            "category": self.category,
        }


@dataclass
class AnalysisResult:
    """Result of analyzing a diff."""

    target: str
    annotations: list[Annotation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        """Generate summary statistics."""
        by_severity: dict[str, int] = {}
        by_lens: dict[str, int] = {}

        for annotation in self.annotations:
            sev = annotation.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            lens = annotation.lens
            by_lens[lens] = by_lens.get(lens, 0) + 1

        return {
            "total": len(self.annotations),
            "by_severity": by_severity,
            "by_lens": by_lens,
        }
