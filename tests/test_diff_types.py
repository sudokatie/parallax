"""Tests for diff types."""

import pytest

from parallax.diff.types import DiffHunk, DiffLine, DiffLineKind, FileDiff, ParsedDiff


class TestDiffLineKind:
    """Tests for DiffLineKind enum."""

    def test_diff_line_kind_values(self):
        """Verify enum values."""
        assert DiffLineKind.ADD.value == "add"
        assert DiffLineKind.REMOVE.value == "remove"
        assert DiffLineKind.CONTEXT.value == "context"


class TestDiffLine:
    """Tests for DiffLine dataclass."""

    def test_diff_line_add(self):
        """Test creating an add line."""
        line = DiffLine(kind=DiffLineKind.ADD, content="new content", old_line=None, new_line=10)
        assert line.kind == DiffLineKind.ADD
        assert line.content == "new content"
        assert line.old_line is None
        assert line.new_line == 10

    def test_diff_line_remove(self):
        """Test creating a remove line."""
        line = DiffLine(
            kind=DiffLineKind.REMOVE, content="old content", old_line=5, new_line=None
        )
        assert line.kind == DiffLineKind.REMOVE
        assert line.old_line == 5
        assert line.new_line is None

    def test_diff_line_context(self):
        """Test creating a context line."""
        line = DiffLine(
            kind=DiffLineKind.CONTEXT, content="unchanged", old_line=5, new_line=10
        )
        assert line.kind == DiffLineKind.CONTEXT
        assert line.old_line == 5
        assert line.new_line == 10

    def test_diff_line_frozen(self):
        """Verify DiffLine is immutable."""
        line = DiffLine(kind=DiffLineKind.ADD, content="test", old_line=None, new_line=1)
        with pytest.raises(AttributeError):
            line.content = "other"


class TestDiffHunk:
    """Tests for DiffHunk dataclass."""

    def test_diff_hunk_creation(self):
        """Test creating a diff hunk."""
        lines = (
            DiffLine(kind=DiffLineKind.CONTEXT, content="ctx", old_line=1, new_line=1),
            DiffLine(kind=DiffLineKind.REMOVE, content="old", old_line=2, new_line=None),
            DiffLine(kind=DiffLineKind.ADD, content="new", old_line=None, new_line=2),
        )
        hunk = DiffHunk(
            old_start=1, old_count=2, new_start=1, new_count=2, lines=lines, header="@@ -1,2 +1,2 @@"
        )
        assert hunk.old_start == 1
        assert hunk.old_count == 2
        assert hunk.new_start == 1
        assert hunk.new_count == 2
        assert len(hunk.lines) == 3

    def test_diff_hunk_added_lines(self):
        """Test getting added line numbers."""
        lines = (
            DiffLine(kind=DiffLineKind.ADD, content="line1", old_line=None, new_line=5),
            DiffLine(kind=DiffLineKind.ADD, content="line2", old_line=None, new_line=6),
            DiffLine(kind=DiffLineKind.CONTEXT, content="ctx", old_line=3, new_line=7),
        )
        hunk = DiffHunk(
            old_start=3, old_count=1, new_start=5, new_count=3, lines=lines, header="@@ -3,1 +5,3 @@"
        )
        assert hunk.added_lines() == {5, 6}

    def test_diff_hunk_removed_lines(self):
        """Test getting removed line numbers."""
        lines = (
            DiffLine(kind=DiffLineKind.REMOVE, content="old1", old_line=10, new_line=None),
            DiffLine(kind=DiffLineKind.REMOVE, content="old2", old_line=11, new_line=None),
            DiffLine(kind=DiffLineKind.CONTEXT, content="ctx", old_line=12, new_line=10),
        )
        hunk = DiffHunk(
            old_start=10, old_count=3, new_start=10, new_count=1, lines=lines, header="@@ -10,3 +10,1 @@"
        )
        assert hunk.removed_lines() == {10, 11}


class TestFileDiff:
    """Tests for FileDiff dataclass."""

    def test_file_diff_normal(self):
        """Test normal file modification."""
        file_diff = FileDiff(old_path="test.py", new_path="test.py", hunks=())
        assert file_diff.path == "test.py"
        assert not file_diff.is_new
        assert not file_diff.is_deleted
        assert not file_diff.is_renamed

    def test_file_diff_new_file(self):
        """Test new file detection."""
        file_diff = FileDiff(old_path=None, new_path="new.py", hunks=())
        assert file_diff.path == "new.py"
        assert file_diff.is_new
        assert not file_diff.is_deleted
        assert not file_diff.is_renamed

    def test_file_diff_deleted_file(self):
        """Test deleted file detection."""
        file_diff = FileDiff(old_path="old.py", new_path=None, hunks=())
        assert file_diff.path == "old.py"
        assert not file_diff.is_new
        assert file_diff.is_deleted
        assert not file_diff.is_renamed

    def test_file_diff_renamed(self):
        """Test renamed file detection."""
        file_diff = FileDiff(old_path="old_name.py", new_path="new_name.py", hunks=())
        assert file_diff.path == "new_name.py"
        assert not file_diff.is_new
        assert not file_diff.is_deleted
        assert file_diff.is_renamed

    def test_file_diff_binary(self):
        """Test binary file flag."""
        file_diff = FileDiff(old_path="image.png", new_path="image.png", hunks=(), is_binary=True)
        assert file_diff.is_binary

    def test_file_diff_no_path_raises(self):
        """Test that accessing path with no paths raises."""
        file_diff = FileDiff(old_path=None, new_path=None, hunks=())
        with pytest.raises(ValueError, match="no path"):
            _ = file_diff.path

    def test_file_diff_changed_lines(self):
        """Test getting all changed lines from file."""
        lines1 = (DiffLine(kind=DiffLineKind.ADD, content="a", old_line=None, new_line=5),)
        lines2 = (
            DiffLine(kind=DiffLineKind.ADD, content="b", old_line=None, new_line=10),
            DiffLine(kind=DiffLineKind.ADD, content="c", old_line=None, new_line=11),
        )
        hunks = (
            DiffHunk(old_start=5, old_count=0, new_start=5, new_count=1, lines=lines1, header="@@"),
            DiffHunk(old_start=10, old_count=0, new_start=10, new_count=2, lines=lines2, header="@@"),
        )
        file_diff = FileDiff(old_path="test.py", new_path="test.py", hunks=hunks)
        assert file_diff.changed_lines() == {5, 10, 11}


class TestParsedDiff:
    """Tests for ParsedDiff dataclass."""

    def test_parsed_diff_empty(self):
        """Test empty diff."""
        diff = ParsedDiff(files=())
        assert len(diff.files) == 0
        assert diff.changed_files == []

    def test_parsed_diff_get_file_by_new_path(self):
        """Test getting file by new path."""
        file1 = FileDiff(old_path="a.py", new_path="a.py", hunks=())
        file2 = FileDiff(old_path="b.py", new_path="b.py", hunks=())
        diff = ParsedDiff(files=(file1, file2))
        assert diff.get_file("a.py") == file1
        assert diff.get_file("b.py") == file2
        assert diff.get_file("c.py") is None

    def test_parsed_diff_get_file_by_old_path(self):
        """Test getting deleted file by old path."""
        file1 = FileDiff(old_path="deleted.py", new_path=None, hunks=())
        diff = ParsedDiff(files=(file1,))
        assert diff.get_file("deleted.py") == file1

    def test_parsed_diff_changed_lines(self):
        """Test getting changed lines for a file."""
        lines = (DiffLine(kind=DiffLineKind.ADD, content="x", old_line=None, new_line=5),)
        hunks = (DiffHunk(old_start=5, old_count=0, new_start=5, new_count=1, lines=lines, header="@@"),)
        file1 = FileDiff(old_path="test.py", new_path="test.py", hunks=hunks)
        diff = ParsedDiff(files=(file1,))
        assert diff.changed_lines("test.py") == {5}
        assert diff.changed_lines("other.py") == set()

    def test_parsed_diff_changed_files(self):
        """Test listing changed files."""
        file1 = FileDiff(old_path="a.py", new_path="a.py", hunks=())
        file2 = FileDiff(old_path=None, new_path="new.py", hunks=())
        file3 = FileDiff(old_path="deleted.py", new_path=None, hunks=())
        diff = ParsedDiff(files=(file1, file2, file3))
        assert diff.changed_files == ["a.py", "new.py", "deleted.py"]
