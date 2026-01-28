"""Base language analyzer interface for Parallax."""

import os
from abc import ABC, abstractmethod
from typing import Optional

import tree_sitter


class FileAST:
    """Wrapper around tree-sitter Tree for a parsed file."""

    def __init__(self, path: str, tree: tree_sitter.Tree, source: bytes):
        """Initialize FileAST.

        Args:
            path: File path.
            tree: Parsed tree-sitter tree.
            source: Original source code as bytes.
        """
        self.path = path
        self.tree = tree
        self.source = source
        self._query_cache: dict[str, tree_sitter.Query] = {}

    @property
    def root(self) -> tree_sitter.Node:
        """Get the root node of the AST."""
        return self.tree.root_node

    def text_at(self, node: tree_sitter.Node) -> str:
        """Get source text for a node.

        Args:
            node: Tree-sitter node.

        Returns:
            The source text corresponding to the node.
        """
        return self.source[node.start_byte:node.end_byte].decode("utf-8")

    def node_at_line(self, line: int) -> Optional[tree_sitter.Node]:
        """Get the smallest node containing the given line.

        Args:
            line: 1-indexed line number.

        Returns:
            The smallest node containing that line, or None if not found.
        """
        # Convert to 0-indexed for tree-sitter
        ts_line = line - 1
        if ts_line < 0:
            return None

        def find_at_line(node: tree_sitter.Node) -> Optional[tree_sitter.Node]:
            # Check if this node spans the target line
            if node.start_point[0] <= ts_line <= node.end_point[0]:
                # Try to find a smaller child that also contains the line
                for child in node.children:
                    if child.start_point[0] <= ts_line <= child.end_point[0]:
                        result = find_at_line(child)
                        if result is not None:
                            return result
                return node
            return None

        return find_at_line(self.root)

    def query(self, pattern: str, language: tree_sitter.Language) -> list[tuple[tree_sitter.Node, str]]:
        """Run a tree-sitter query and return matches.

        Args:
            pattern: Tree-sitter query pattern (S-expression).
            language: Language for the query.

        Returns:
            List of (node, capture_name) tuples.
        """
        if pattern not in self._query_cache:
            self._query_cache[pattern] = language.query(pattern)

        query = self._query_cache[pattern]
        captures = query.captures(self.root)

        # tree-sitter-python returns list of (node, name) tuples
        return captures

    def find_nodes_by_type(self, node_type: str) -> list[tree_sitter.Node]:
        """Find all nodes of a given type.

        Args:
            node_type: The type of node to find (e.g., 'function_definition').

        Returns:
            List of matching nodes.
        """
        results: list[tree_sitter.Node] = []

        def visit(node: tree_sitter.Node) -> None:
            if node.type == node_type:
                results.append(node)
            for child in node.children:
                visit(child)

        visit(self.root)
        return results

    def line_to_point(self, line: int) -> tuple[int, int]:
        """Convert 1-indexed line to tree-sitter point.

        Args:
            line: 1-indexed line number.

        Returns:
            (row, column) tuple with 0-indexed row.
        """
        return (line - 1, 0)


class LanguageAnalyzer(ABC):
    """Abstract base class for language analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this language."""
        pass

    @property
    @abstractmethod
    def extensions(self) -> set[str]:
        """File extensions this analyzer handles (e.g., {'.py', '.pyi'})."""
        pass

    @abstractmethod
    def parse_file(self, path: str) -> FileAST:
        """Parse a file and return its AST.

        Args:
            path: Path to the file.

        Returns:
            FileAST for the parsed file.

        Raises:
            FileNotFoundError: If file doesn't exist.
            ParseError: If file cannot be parsed.
        """
        pass

    @abstractmethod
    def parse_source(self, source: str, path: str = "<string>") -> FileAST:
        """Parse source code string and return its AST.

        Args:
            source: Source code as string.
            path: Virtual path for the source (for error messages).

        Returns:
            FileAST for the parsed source.
        """
        pass

    def supports_file(self, path: str) -> bool:
        """Check if this analyzer can handle the given file.

        Args:
            path: File path.

        Returns:
            True if the file extension is supported.
        """
        ext = os.path.splitext(path)[1]
        return ext in self.extensions
