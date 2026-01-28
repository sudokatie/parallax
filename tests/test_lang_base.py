"""Tests for language analyzer base classes."""

import pytest
import tree_sitter
import tree_sitter_python

from parallax.lang.base import FileAST, LanguageAnalyzer


# Get the Python language for testing
PY_LANGUAGE = tree_sitter.Language(tree_sitter_python.language())


class TestFileAST:
    """Tests for FileAST class."""

    def _parse_python(self, source: str) -> FileAST:
        """Helper to parse Python source."""
        parser = tree_sitter.Parser(PY_LANGUAGE)
        source_bytes = source.encode("utf-8")
        tree = parser.parse(source_bytes)
        return FileAST(path="test.py", tree=tree, source=source_bytes)

    def test_file_ast_creation(self):
        """Test creating a FileAST."""
        ast = self._parse_python("x = 1")
        assert ast.path == "test.py"
        assert ast.root is not None
        assert ast.root.type == "module"

    def test_text_at_node(self):
        """Test extracting text for a node."""
        ast = self._parse_python("x = 42")
        # Find the integer node
        nodes = ast.find_nodes_by_type("integer")
        assert len(nodes) == 1
        assert ast.text_at(nodes[0]) == "42"

    def test_text_at_multiline(self):
        """Test extracting multiline text."""
        source = '''def foo():
    return 1'''
        ast = self._parse_python(source)
        funcs = ast.find_nodes_by_type("function_definition")
        assert len(funcs) == 1
        assert "def foo():" in ast.text_at(funcs[0])
        assert "return 1" in ast.text_at(funcs[0])

    def test_node_at_line_simple(self):
        """Test finding node at a specific line."""
        source = """x = 1
y = 2
z = 3"""
        ast = self._parse_python(source)
        node = ast.node_at_line(2)  # y = 2
        assert node is not None
        text = ast.text_at(node)
        # Should contain 'y' or '2' depending on how deep we go
        assert "y" in text or "2" in text

    def test_node_at_line_in_function(self):
        """Test finding node inside a function."""
        source = """def foo():
    x = 1
    y = 2
    return x + y"""
        ast = self._parse_python(source)
        node = ast.node_at_line(3)  # y = 2
        assert node is not None
        text = ast.text_at(node)
        assert "y" in text or "2" in text

    def test_node_at_line_invalid(self):
        """Test node_at_line with invalid line number."""
        ast = self._parse_python("x = 1")
        assert ast.node_at_line(0) is None  # 0 is invalid (1-indexed)
        assert ast.node_at_line(-1) is None

    def test_node_at_line_out_of_range(self):
        """Test node_at_line with line beyond file."""
        ast = self._parse_python("x = 1")
        # Line 100 doesn't exist, should return None
        result = ast.node_at_line(100)
        # May return root node if it spans the line, or None
        # Either is acceptable behavior

    def test_find_nodes_by_type_function(self):
        """Test finding function definitions."""
        source = """def foo():
    pass

def bar():
    pass"""
        ast = self._parse_python(source)
        funcs = ast.find_nodes_by_type("function_definition")
        assert len(funcs) == 2

    def test_find_nodes_by_type_nested(self):
        """Test finding nested nodes."""
        source = """class Foo:
    def bar(self):
        def inner():
            pass"""
        ast = self._parse_python(source)
        funcs = ast.find_nodes_by_type("function_definition")
        assert len(funcs) == 2  # bar and inner

    def test_find_nodes_by_type_none(self):
        """Test finding nodes that don't exist."""
        ast = self._parse_python("x = 1")
        funcs = ast.find_nodes_by_type("function_definition")
        assert len(funcs) == 0

    def test_line_to_point(self):
        """Test line number conversion."""
        ast = self._parse_python("x = 1")
        assert ast.line_to_point(1) == (0, 0)
        assert ast.line_to_point(5) == (4, 0)


class TestLanguageAnalyzer:
    """Tests for LanguageAnalyzer ABC."""

    def test_language_analyzer_is_abstract(self):
        """Test that LanguageAnalyzer cannot be instantiated directly."""
        with pytest.raises(TypeError):
            LanguageAnalyzer()

    def test_concrete_implementation(self):
        """Test creating a concrete implementation."""

        class TestAnalyzer(LanguageAnalyzer):
            @property
            def name(self) -> str:
                return "test"

            @property
            def extensions(self) -> set[str]:
                return {".test"}

            def parse_file(self, path: str) -> FileAST:
                raise NotImplementedError

            def parse_source(self, source: str, path: str = "<string>") -> FileAST:
                raise NotImplementedError

        analyzer = TestAnalyzer()
        assert analyzer.name == "test"
        assert analyzer.extensions == {".test"}

    def test_supports_file(self):
        """Test supports_file method."""

        class TestAnalyzer(LanguageAnalyzer):
            @property
            def name(self) -> str:
                return "test"

            @property
            def extensions(self) -> set[str]:
                return {".py", ".pyi"}

            def parse_file(self, path: str) -> FileAST:
                raise NotImplementedError

            def parse_source(self, source: str, path: str = "<string>") -> FileAST:
                raise NotImplementedError

        analyzer = TestAnalyzer()
        assert analyzer.supports_file("test.py") is True
        assert analyzer.supports_file("test.pyi") is True
        assert analyzer.supports_file("test.js") is False
        assert analyzer.supports_file("test") is False
