"""Inline suppression handling for Parallax.

Supports three suppression comment styles:
- # parallax-ignore <rule>  - Suppress on same line
- # parallax-ignore-next-line <rule>  - Suppress on next line
- # parallax-ignore-file <rule>  - Suppress entire file
"""

import fnmatch
import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Suppression:
    """A suppression directive from source code."""

    rule_pattern: str  # e.g., "security/sql-injection" or "security/*"
    line: Optional[int]  # None for file-level suppression
    is_next_line: bool  # True if suppresses next line, False if same line


class SuppressionParser:
    """Parse suppression comments from source code."""

    # Regex patterns for suppression comments
    IGNORE_PATTERN = re.compile(
        r"#\s*parallax-ignore\s+([a-zA-Z0-9_/*-]+)", re.IGNORECASE
    )
    IGNORE_NEXT_LINE_PATTERN = re.compile(
        r"#\s*parallax-ignore-next-line\s+([a-zA-Z0-9_/*-]+)", re.IGNORECASE
    )
    IGNORE_FILE_PATTERN = re.compile(
        r"#\s*parallax-ignore-file\s+([a-zA-Z0-9_/*-]+)", re.IGNORECASE
    )

    def parse(self, source: str) -> list[Suppression]:
        """Parse all suppression comments from source code.

        Args:
            source: Source code as string.

        Returns:
            List of Suppression objects.
        """
        suppressions: list[Suppression] = []
        lines = source.split("\n")

        for i, line in enumerate(lines):
            line_num = i + 1  # 1-indexed

            # Check for file-level suppression (can be anywhere but typically at top)
            match = self.IGNORE_FILE_PATTERN.search(line)
            if match:
                suppressions.append(
                    Suppression(
                        rule_pattern=match.group(1),
                        line=None,
                        is_next_line=False,
                    )
                )
                continue

            # Check for next-line suppression
            match = self.IGNORE_NEXT_LINE_PATTERN.search(line)
            if match:
                suppressions.append(
                    Suppression(
                        rule_pattern=match.group(1),
                        line=line_num + 1,  # Suppresses next line
                        is_next_line=True,
                    )
                )
                continue

            # Check for same-line suppression
            match = self.IGNORE_PATTERN.search(line)
            if match:
                suppressions.append(
                    Suppression(
                        rule_pattern=match.group(1),
                        line=line_num,
                        is_next_line=False,
                    )
                )

        return suppressions


class SuppressionChecker:
    """Check if annotations should be suppressed."""

    def __init__(self, suppressions: dict[str, list[Suppression]]) -> None:
        """Initialize with suppressions by file path.

        Args:
            suppressions: Dict mapping file paths to their suppressions.
        """
        self._suppressions = suppressions

    def is_suppressed(self, file: str, line: int, rule_id: str) -> bool:
        """Check if a finding at file:line with rule_id should be suppressed.

        Args:
            file: File path.
            line: Line number (1-indexed).
            rule_id: Rule identifier (e.g., "security/sql-injection").

        Returns:
            True if the finding should be suppressed.
        """
        file_suppressions = self._suppressions.get(file, [])

        for suppression in file_suppressions:
            # Check if rule matches the pattern
            if not self._rule_matches(rule_id, suppression.rule_pattern):
                continue

            # File-level suppression
            if suppression.line is None:
                return True

            # Line-specific suppression
            if suppression.line == line:
                return True

        return False

    def _rule_matches(self, rule_id: str, pattern: str) -> bool:
        """Check if a rule_id matches a suppression pattern.

        Args:
            rule_id: Full rule ID like "security/sql-injection".
            pattern: Pattern which may include wildcards like "security/*".

        Returns:
            True if the rule matches the pattern.
        """
        # Exact match
        if rule_id == pattern:
            return True

        # Wildcard match
        if "*" in pattern:
            return fnmatch.fnmatch(rule_id, pattern)

        return False


def parse_file_suppressions(source: str) -> list[Suppression]:
    """Parse suppression comments from source code.

    Args:
        source: Source code as string.

    Returns:
        List of Suppression objects.
    """
    parser = SuppressionParser()
    return parser.parse(source)
