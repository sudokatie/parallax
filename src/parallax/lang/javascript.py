"""JavaScript/TypeScript language analyzer for Parallax."""

from pathlib import Path
from typing import Optional

import tree_sitter
import tree_sitter_javascript
import tree_sitter_typescript

from parallax.lang.base import FileAST, LanguageAnalyzer


class JavaScriptAnalyzer(LanguageAnalyzer):
    """JavaScript language analyzer using tree-sitter."""

    def __init__(self) -> None:
        """Initialize the JavaScript analyzer."""
        self._language = tree_sitter.Language(tree_sitter_javascript.language())
        self._parser = tree_sitter.Parser(self._language)

    @property
    def name(self) -> str:
        return "javascript"

    @property
    def extensions(self) -> set[str]:
        return {".js", ".jsx", ".mjs", ".cjs"}

    @property
    def language(self) -> tree_sitter.Language:
        """Get the tree-sitter language object."""
        return self._language

    def parse_file(self, path: str) -> FileAST:
        """Parse a JavaScript file.

        Args:
            path: Path to the JavaScript file.

        Returns:
            FileAST for the parsed file.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        filepath = Path(path)
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {path}")

        source = filepath.read_bytes()
        tree = self._parser.parse(source)
        return FileAST(path=path, tree=tree, source=source)

    def parse_source(self, source: str, path: str = "<source>") -> FileAST:
        """Parse JavaScript source code.

        Args:
            source: JavaScript source code.
            path: Virtual path for the source.

        Returns:
            FileAST for the parsed source.
        """
        source_bytes = source.encode("utf-8")
        tree = self._parser.parse(source_bytes)
        return FileAST(path=path, tree=tree, source=source_bytes)

    def find_function_at_line(self, ast: FileAST, line: int) -> Optional[str]:
        """Find the function name containing a line.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            Function name or None if not in a function.
        """
        node = ast.node_at_line(line)
        if node is None:
            return None

        # Walk up to find containing function
        current = node
        while current is not None:
            if current.type in ("function_declaration", "method_definition",
                               "arrow_function", "function_expression"):
                # Get function name
                if current.type == "function_declaration":
                    name_node = current.child_by_field_name("name")
                    if name_node:
                        return ast.text_at(name_node)
                elif current.type == "method_definition":
                    name_node = current.child_by_field_name("name")
                    if name_node:
                        return ast.text_at(name_node)
                elif current.type in ("arrow_function", "function_expression"):
                    # Check if assigned to variable
                    parent = current.parent
                    if parent and parent.type == "variable_declarator":
                        name_node = parent.child_by_field_name("name")
                        if name_node:
                            return ast.text_at(name_node)
                    return "<anonymous>"
            current = current.parent

        return None

    def find_class_at_line(self, ast: FileAST, line: int) -> Optional[str]:
        """Find the class name containing a line.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            Class name or None if not in a class.
        """
        node = ast.node_at_line(line)
        if node is None:
            return None

        current = node
        while current is not None:
            if current.type == "class_declaration":
                name_node = current.child_by_field_name("name")
                if name_node:
                    return ast.text_at(name_node)
            current = current.parent

        return None

    def is_in_loop(self, ast: FileAST, line: int) -> bool:
        """Check if a line is inside a loop.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            True if line is inside a loop.
        """
        node = ast.node_at_line(line)
        if node is None:
            return False

        current = node
        while current is not None:
            if current.type in ("for_statement", "for_in_statement",
                               "while_statement", "do_statement"):
                return True
            current = current.parent

        return False

    def get_imports(self, ast: FileAST) -> list[str]:
        """Get all import statements.

        Args:
            ast: The parsed AST.

        Returns:
            List of imported module names.
        """
        imports = []

        # Find import statements
        import_nodes = ast.find_nodes_by_type("import_statement")
        for node in import_nodes:
            # Get the source (the module being imported)
            source = node.child_by_field_name("source")
            if source:
                text = ast.text_at(source)
                # Remove quotes
                if text.startswith('"') or text.startswith("'"):
                    text = text[1:-1]
                imports.append(text)

        # Also check for require calls
        call_nodes = ast.find_nodes_by_type("call_expression")
        for call in call_nodes:
            func = call.child_by_field_name("function")
            if func and ast.text_at(func) == "require":
                args = call.child_by_field_name("arguments")
                if args:
                    for child in args.children:
                        if child.type == "string":
                            text = ast.text_at(child)
                            if text.startswith('"') or text.startswith("'"):
                                text = text[1:-1]
                            imports.append(text)

        return imports


class TypeScriptAnalyzer(LanguageAnalyzer):
    """TypeScript language analyzer using tree-sitter."""

    def __init__(self) -> None:
        """Initialize the TypeScript analyzer."""
        self._language = tree_sitter.Language(tree_sitter_typescript.language_typescript())
        self._tsx_language = tree_sitter.Language(tree_sitter_typescript.language_tsx())
        self._parser = tree_sitter.Parser(self._language)
        self._tsx_parser = tree_sitter.Parser(self._tsx_language)

    @property
    def name(self) -> str:
        return "typescript"

    @property
    def extensions(self) -> set[str]:
        return {".ts", ".tsx", ".mts", ".cts"}

    @property
    def language(self) -> tree_sitter.Language:
        """Get the tree-sitter language object."""
        return self._language

    def _get_parser(self, path: str) -> tree_sitter.Parser:
        """Get appropriate parser based on file extension."""
        if path.endswith(".tsx"):
            return self._tsx_parser
        return self._parser

    def parse_file(self, path: str) -> FileAST:
        """Parse a TypeScript file.

        Args:
            path: Path to the TypeScript file.

        Returns:
            FileAST for the parsed file.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        filepath = Path(path)
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {path}")

        source = filepath.read_bytes()
        parser = self._get_parser(path)
        tree = parser.parse(source)
        return FileAST(path=path, tree=tree, source=source)

    def parse_source(self, source: str, path: str = "<source>") -> FileAST:
        """Parse TypeScript source code.

        Args:
            source: TypeScript source code.
            path: Virtual path for the source.

        Returns:
            FileAST for the parsed source.
        """
        source_bytes = source.encode("utf-8")
        parser = self._get_parser(path)
        tree = parser.parse(source_bytes)
        return FileAST(path=path, tree=tree, source=source_bytes)

    def find_function_at_line(self, ast: FileAST, line: int) -> Optional[str]:
        """Find the function name containing a line.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            Function name or None if not in a function.
        """
        node = ast.node_at_line(line)
        if node is None:
            return None

        current = node
        while current is not None:
            if current.type in ("function_declaration", "method_definition",
                               "arrow_function", "function_expression"):
                if current.type == "function_declaration":
                    name_node = current.child_by_field_name("name")
                    if name_node:
                        return ast.text_at(name_node)
                elif current.type == "method_definition":
                    name_node = current.child_by_field_name("name")
                    if name_node:
                        return ast.text_at(name_node)
                elif current.type in ("arrow_function", "function_expression"):
                    parent = current.parent
                    if parent and parent.type == "variable_declarator":
                        name_node = parent.child_by_field_name("name")
                        if name_node:
                            return ast.text_at(name_node)
                    return "<anonymous>"
            current = current.parent

        return None

    def find_class_at_line(self, ast: FileAST, line: int) -> Optional[str]:
        """Find the class name containing a line.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            Class name or None if not in a class.
        """
        node = ast.node_at_line(line)
        if node is None:
            return None

        current = node
        while current is not None:
            if current.type == "class_declaration":
                name_node = current.child_by_field_name("name")
                if name_node:
                    return ast.text_at(name_node)
            current = current.parent

        return None

    def is_in_loop(self, ast: FileAST, line: int) -> bool:
        """Check if a line is inside a loop.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            True if line is inside a loop.
        """
        node = ast.node_at_line(line)
        if node is None:
            return False

        current = node
        while current is not None:
            if current.type in ("for_statement", "for_in_statement",
                               "while_statement", "do_statement"):
                return True
            current = current.parent

        return False

    def get_imports(self, ast: FileAST) -> list[str]:
        """Get all import statements.

        Args:
            ast: The parsed AST.

        Returns:
            List of imported module names.
        """
        imports = []

        # Find import statements
        import_nodes = ast.find_nodes_by_type("import_statement")
        for node in import_nodes:
            source = node.child_by_field_name("source")
            if source:
                text = ast.text_at(source)
                if text.startswith('"') or text.startswith("'"):
                    text = text[1:-1]
                imports.append(text)

        return imports

    def get_type_annotations(self, ast: FileAST, line: int) -> Optional[str]:
        """Get type annotation at a line.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            Type annotation string or None.
        """
        node = ast.node_at_line(line)
        if node is None:
            return None

        # Walk up the tree looking for declarations with type annotations
        current = node
        while current is not None:
            # Check direct children for type_annotation
            for child in current.children:
                if child.type == "type_annotation":
                    return ast.text_at(child)

            # Also check for lexical_declaration -> variable_declarator -> type_annotation
            if current.type == "lexical_declaration":
                for decl in current.children:
                    if decl.type == "variable_declarator":
                        for child in decl.children:
                            if child.type == "type_annotation":
                                return ast.text_at(child)

            current = current.parent

        return None
