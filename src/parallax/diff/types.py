"""Diff data structures for Parallax."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class DiffLineKind(Enum):
    """Type of line in a diff."""

    ADD = "add"
    REMOVE = "remove"
    CONTEXT = "context"


@dataclass(frozen=True)
class DiffLine:
    """A single line in a diff hunk."""

    kind: DiffLineKind
    content: str
    old_line: Optional[int]
    new_line: Optional[int]


@dataclass(frozen=True)
class DiffHunk:
    """A contiguous changed section in a file diff."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[DiffLine, ...]
    header: str

    def added_lines(self) -> set[int]:
        """Return set of added line numbers (in new file)."""
        return {line.new_line for line in self.lines if line.kind == DiffLineKind.ADD and line.new_line is not None}

    def removed_lines(self) -> set[int]:
        """Return set of removed line numbers (in old file)."""
        return {line.old_line for line in self.lines if line.kind == DiffLineKind.REMOVE and line.old_line is not None}


@dataclass(frozen=True)
class FileDiff:
    """Changes to a single file."""

    old_path: Optional[str]
    new_path: Optional[str]
    hunks: tuple[DiffHunk, ...]
    is_binary: bool = False

    @property
    def path(self) -> str:
        """Return the current path (new_path if exists, else old_path)."""
        if self.new_path is not None:
            return self.new_path
        if self.old_path is not None:
            return self.old_path
        raise ValueError("FileDiff has no path")

    @property
    def is_new(self) -> bool:
        """Check if this is a new file."""
        return self.old_path is None and self.new_path is not None

    @property
    def is_deleted(self) -> bool:
        """Check if this file was deleted."""
        return self.old_path is not None and self.new_path is None

    @property
    def is_renamed(self) -> bool:
        """Check if this file was renamed."""
        return self.old_path is not None and self.new_path is not None and self.old_path != self.new_path

    def changed_lines(self) -> set[int]:
        """Return set of all changed line numbers in new file (added lines)."""
        result: set[int] = set()
        for hunk in self.hunks:
            result.update(hunk.added_lines())
        return result


@dataclass(frozen=True)
class ParsedDiff:
    """A complete parsed diff."""

    files: tuple[FileDiff, ...]

    def get_file(self, path: str) -> Optional[FileDiff]:
        """Get FileDiff by path (matches old_path or new_path)."""
        for file_diff in self.files:
            if file_diff.new_path == path or file_diff.old_path == path:
                return file_diff
        return None

    def changed_lines(self, path: str) -> set[int]:
        """Get changed line numbers for a specific file."""
        file_diff = self.get_file(path)
        if file_diff is None:
            return set()
        return file_diff.changed_lines()

    @property
    def changed_files(self) -> list[str]:
        """List of all changed file paths."""
        paths = []
        for file_diff in self.files:
            if file_diff.new_path:
                paths.append(file_diff.new_path)
            elif file_diff.old_path:
                paths.append(file_diff.old_path)
        return paths
