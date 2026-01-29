"""Unified diff parser for Parallax."""

import re
from pathlib import Path

from parallax.diff.types import DiffHunk, DiffLine, DiffLineKind, FileDiff, ParsedDiff


class ParseError(Exception):
    """Error parsing diff content."""

    pass


# Regex patterns for parsing
DIFF_GIT_HEADER = re.compile(r"^diff --git a/(.*) b/(.*)$")
OLD_FILE_HEADER = re.compile(r"^--- (?:a/)?(.+?)(?:\t.*)?$")
NEW_FILE_HEADER = re.compile(r"^\+\+\+ (?:b/)?(.+?)(?:\t.*)?$")
HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")
BINARY_FILES = re.compile(r"^Binary files .* and .* differ$")


def parse_diff(content: str) -> ParsedDiff:
    """Parse unified diff content string.

    Args:
        content: The unified diff content as a string.

    Returns:
        ParsedDiff containing all file changes.

    Raises:
        ParseError: If the diff content is malformed.
    """
    if not content or not content.strip():
        return ParsedDiff(files=())

    lines = content.splitlines()
    files: list[FileDiff] = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Skip empty lines and git metadata
        if not line or line.startswith("index ") or line.startswith("new file mode"):
            i += 1
            continue

        # Check for diff --git header
        git_match = DIFF_GIT_HEADER.match(line)
        if git_match:
            file_diff, i = _parse_file_diff(lines, i)
            if file_diff is not None:
                files.append(file_diff)
            continue

        # Check for --- header (non-git diff)
        if line.startswith("---"):
            file_diff, i = _parse_file_diff(lines, i)
            if file_diff is not None:
                files.append(file_diff)
            continue

        i += 1

    return ParsedDiff(files=tuple(files))


def parse_diff_file(path: str) -> ParsedDiff:
    """Parse diff from a file.

    Args:
        path: Path to the diff/patch file.

    Returns:
        ParsedDiff containing all file changes.

    Raises:
        ParseError: If the file cannot be read or parsed.
        FileNotFoundError: If the file does not exist.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Diff file not found: {path}")

    try:
        content = filepath.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            content = filepath.read_text(encoding="latin-1")
        except Exception as e:
            raise ParseError(f"Cannot read diff file: {e}") from e

    return parse_diff(content)


def _parse_file_diff(lines: list[str], start: int) -> tuple[FileDiff | None, int]:
    """Parse a single file's diff section.

    Returns:
        Tuple of (FileDiff or None, next line index)
    """
    i = start
    old_path: str | None = None
    new_path: str | None = None
    hunks: list[DiffHunk] = []
    is_binary = False

    # Handle diff --git header
    if i < len(lines):
        git_match = DIFF_GIT_HEADER.match(lines[i])
        if git_match:
            # Tentative paths from git header
            old_path = git_match.group(1)
            new_path = git_match.group(2)
            i += 1

    # Skip metadata lines
    while i < len(lines):
        line = lines[i]
        if (
            line.startswith("index ")
            or line.startswith("new file mode")
            or line.startswith("deleted file mode")
        ):
            if "deleted file mode" in line:
                # Mark for deletion detection later
                pass
            i += 1
            continue
        if line.startswith("old mode") or line.startswith("new mode"):
            i += 1
            continue
        if (
            line.startswith("similarity index")
            or line.startswith("rename from")
            or line.startswith("rename to")
        ):
            i += 1
            continue
        break

    # Check for binary file marker
    if i < len(lines) and BINARY_FILES.match(lines[i]):
        is_binary = True
        i += 1
        # Return binary file diff
        if old_path is None and new_path is None:
            return None, i
        return FileDiff(old_path=old_path, new_path=new_path, hunks=(), is_binary=True), i

    # Parse --- header
    if i < len(lines) and lines[i].startswith("---"):
        old_match = OLD_FILE_HEADER.match(lines[i])
        if old_match:
            path_str = old_match.group(1)
            old_path = None if path_str == "/dev/null" else path_str
        i += 1

    # Parse +++ header
    if i < len(lines) and lines[i].startswith("+++"):
        new_match = NEW_FILE_HEADER.match(lines[i])
        if new_match:
            path_str = new_match.group(1)
            new_path = None if path_str == "/dev/null" else path_str
        i += 1

    # Parse hunks
    while i < len(lines):
        line = lines[i]

        # Check for next file or end
        if DIFF_GIT_HEADER.match(line) or (
            line.startswith("---") and i + 1 < len(lines) and lines[i + 1].startswith("+++")
        ):
            break

        # Check for hunk header
        hunk_match = HUNK_HEADER.match(line)
        if hunk_match:
            hunk, i = _parse_hunk(lines, i, hunk_match)
            hunks.append(hunk)
            continue

        i += 1

    if old_path is None and new_path is None:
        return None, i

    return (
        FileDiff(old_path=old_path, new_path=new_path, hunks=tuple(hunks), is_binary=is_binary),
        i,
    )


def _parse_hunk(lines: list[str], start: int, hunk_match: re.Match) -> tuple[DiffHunk, int]:
    """Parse a single hunk.

    Returns:
        Tuple of (DiffHunk, next line index)
    """
    old_start = int(hunk_match.group(1))
    old_count = int(hunk_match.group(2)) if hunk_match.group(2) else 1
    new_start = int(hunk_match.group(3))
    new_count = int(hunk_match.group(4)) if hunk_match.group(4) else 1
    header = lines[start]

    hunk_lines: list[DiffLine] = []
    old_line = old_start
    new_line = new_start
    i = start + 1

    while i < len(lines):
        line = lines[i]

        # Check for end of hunk
        if not line:
            i += 1
            continue
        if line.startswith("@@") or line.startswith("diff --git") or line.startswith("---"):
            break
        if line.startswith("\\ No newline at end of file"):
            i += 1
            continue

        # Parse line type
        if line.startswith("+"):
            hunk_lines.append(
                DiffLine(
                    kind=DiffLineKind.ADD,
                    content=line[1:],
                    old_line=None,
                    new_line=new_line,
                )
            )
            new_line += 1
        elif line.startswith("-"):
            hunk_lines.append(
                DiffLine(
                    kind=DiffLineKind.REMOVE,
                    content=line[1:],
                    old_line=old_line,
                    new_line=None,
                )
            )
            old_line += 1
        elif line.startswith(" ") or line == "":
            # Context line (or empty context line)
            content = line[1:] if line.startswith(" ") else ""
            hunk_lines.append(
                DiffLine(
                    kind=DiffLineKind.CONTEXT,
                    content=content,
                    old_line=old_line,
                    new_line=new_line,
                )
            )
            old_line += 1
            new_line += 1
        else:
            # Unknown line - might be end of hunk
            break

        i += 1

    return (
        DiffHunk(
            old_start=old_start,
            old_count=old_count,
            new_start=new_start,
            new_count=new_count,
            lines=tuple(hunk_lines),
            header=header,
        ),
        i,
    )
