"""Tests for diff parser."""

from pathlib import Path

import pytest

from parallax.diff.parser import ParseError, parse_diff, parse_diff_file
from parallax.diff.types import DiffLineKind


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "diffs"


class TestParseDiff:
    """Tests for parse_diff function."""

    def test_parse_empty_diff(self):
        """Test parsing empty content."""
        result = parse_diff("")
        assert len(result.files) == 0

    def test_parse_whitespace_only(self):
        """Test parsing whitespace-only content."""
        result = parse_diff("   \n\n   ")
        assert len(result.files) == 0

    def test_parse_simple_add(self):
        """Test parsing a diff with added lines."""
        content = (FIXTURES_DIR / "simple_add.patch").read_text()
        result = parse_diff(content)

        assert len(result.files) == 1
        file_diff = result.files[0]
        assert file_diff.path == "test.py"
        assert not file_diff.is_new
        assert not file_diff.is_deleted
        assert len(file_diff.hunks) == 1

        hunk = file_diff.hunks[0]
        added = [l for l in hunk.lines if l.kind == DiffLineKind.ADD]
        assert len(added) == 2
        assert added[0].content == '    print("world")'
        assert added[1].content == "    return True"

    def test_parse_simple_delete(self):
        """Test parsing a diff with deleted lines."""
        content = (FIXTURES_DIR / "simple_delete.patch").read_text()
        result = parse_diff(content)

        assert len(result.files) == 1
        file_diff = result.files[0]
        hunk = file_diff.hunks[0]

        removed = [l for l in hunk.lines if l.kind == DiffLineKind.REMOVE]
        assert len(removed) == 2
        assert removed[0].content == '    print("world")'
        assert removed[1].content == "    return True"

    def test_parse_multi_file(self):
        """Test parsing a diff with multiple files."""
        content = (FIXTURES_DIR / "multi_file.patch").read_text()
        result = parse_diff(content)

        assert len(result.files) == 2
        assert result.files[0].path == "foo.py"
        assert result.files[1].path == "bar.py"

        # Check foo.py
        foo = result.get_file("foo.py")
        assert foo is not None
        assert len(foo.hunks) == 1
        assert 3 in foo.changed_lines()  # Line 3 added "return 1"

        # Check bar.py
        bar = result.get_file("bar.py")
        assert bar is not None
        assert 8 in bar.changed_lines()  # Line 8 added "w = 4" (at position 5+3)

    def test_parse_new_file(self):
        """Test parsing a diff creating a new file."""
        content = (FIXTURES_DIR / "new_file.patch").read_text()
        result = parse_diff(content)

        assert len(result.files) == 1
        file_diff = result.files[0]
        assert file_diff.is_new
        assert file_diff.old_path is None
        assert file_diff.new_path == "newfile.py"
        assert file_diff.path == "newfile.py"

        # All lines should be additions
        hunk = file_diff.hunks[0]
        assert all(l.kind == DiffLineKind.ADD for l in hunk.lines)
        assert len(hunk.lines) == 5

    def test_parse_deleted_file(self):
        """Test parsing a diff deleting a file."""
        content = (FIXTURES_DIR / "deleted_file.patch").read_text()
        result = parse_diff(content)

        assert len(result.files) == 1
        file_diff = result.files[0]
        assert file_diff.is_deleted
        assert file_diff.old_path == "oldfile.py"
        assert file_diff.new_path is None
        assert file_diff.path == "oldfile.py"

        # All lines should be removals
        hunk = file_diff.hunks[0]
        assert all(l.kind == DiffLineKind.REMOVE for l in hunk.lines)

    def test_parse_binary_file(self):
        """Test parsing a diff with binary files."""
        content = (FIXTURES_DIR / "binary.patch").read_text()
        result = parse_diff(content)

        assert len(result.files) == 1
        file_diff = result.files[0]
        assert file_diff.is_binary
        assert file_diff.path == "image.png"
        assert len(file_diff.hunks) == 0

    def test_parse_hunk_line_numbers(self):
        """Test that line numbers are tracked correctly in hunks."""
        content = (FIXTURES_DIR / "simple_add.patch").read_text()
        result = parse_diff(content)

        hunk = result.files[0].hunks[0]
        # @@ -1,3 +1,5 @@
        assert hunk.old_start == 1
        assert hunk.old_count == 3
        assert hunk.new_start == 1
        assert hunk.new_count == 5

    def test_parse_context_lines(self):
        """Test that context lines have both old and new line numbers."""
        content = (FIXTURES_DIR / "simple_add.patch").read_text()
        result = parse_diff(content)

        hunk = result.files[0].hunks[0]
        context_lines = [l for l in hunk.lines if l.kind == DiffLineKind.CONTEXT]

        for line in context_lines:
            assert line.old_line is not None
            assert line.new_line is not None

    def test_parse_inline_diff(self):
        """Test parsing a diff without git header (traditional unified diff)."""
        content = """--- a/test.py
+++ b/test.py
@@ -1,3 +1,4 @@
 line1
 line2
+line3
 line4
"""
        result = parse_diff(content)
        assert len(result.files) == 1
        assert result.files[0].path == "test.py"

    def test_parse_hunk_count_one_omitted(self):
        """Test parsing hunk header where count of 1 is omitted."""
        content = """diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -5 +5,2 @@
 existing
+added
"""
        result = parse_diff(content)
        hunk = result.files[0].hunks[0]
        assert hunk.old_count == 1
        assert hunk.new_count == 2


class TestParseDiffFile:
    """Tests for parse_diff_file function."""

    def test_parse_existing_file(self):
        """Test parsing an existing diff file."""
        path = FIXTURES_DIR / "simple_add.patch"
        result = parse_diff_file(str(path))
        assert len(result.files) == 1

    def test_parse_nonexistent_file(self):
        """Test parsing a file that doesn't exist."""
        with pytest.raises(FileNotFoundError):
            parse_diff_file("/nonexistent/path/to/file.patch")


class TestChangedLines:
    """Tests for changed line tracking."""

    def test_changed_lines_simple(self):
        """Test getting changed lines from a simple diff."""
        content = (FIXTURES_DIR / "simple_add.patch").read_text()
        result = parse_diff(content)

        changed = result.changed_lines("test.py")
        assert 3 in changed  # print("world")
        assert 4 in changed  # return True

    def test_changed_lines_multi_hunk(self):
        """Test getting changed lines from multiple hunks."""
        content = """diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1,3 +1,4 @@
 line1
+added1
 line2
 line3
@@ -10,3 +11,4 @@
 line10
 line11
+added2
 line12
"""
        result = parse_diff(content)
        changed = result.changed_lines("test.py")
        assert 2 in changed  # added1
        assert 13 in changed  # added2

    def test_changed_lines_nonexistent_file(self):
        """Test getting changed lines for a file not in the diff."""
        content = (FIXTURES_DIR / "simple_add.patch").read_text()
        result = parse_diff(content)
        assert result.changed_lines("nonexistent.py") == set()
