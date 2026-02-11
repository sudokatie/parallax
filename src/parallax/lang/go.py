"""Go language analyzer for Parallax."""

from pathlib import Path
from typing import Optional

import tree_sitter
import tree_sitter_go

from parallax.lang.base import FileAST, LanguageAnalyzer


class GoAnalyzer(LanguageAnalyzer):
    """Go language analyzer using tree-sitter."""

    def __init__(self) -> None:
        """Initialize the Go analyzer."""
        self._language = tree_sitter.Language(tree_sitter_go.language())
        self._parser = tree_sitter.Parser(self._language)

    @property
    def name(self) -> str:
        return "go"

    @property
    def extensions(self) -> set[str]:
        return {".go"}

    @property
    def language(self) -> tree_sitter.Language:
        """Get the tree-sitter language object."""
        return self._language

    def parse_file(self, path: str) -> FileAST:
        """Parse a Go file.

        Args:
            path: Path to the Go file.

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
        """Parse Go source code.

        Args:
            source: Go source code.
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

        current = node
        while current is not None:
            if current.type == "function_declaration":
                name_node = current.child_by_field_name("name")
                if name_node:
                    return ast.text_at(name_node)
            elif current.type == "method_declaration":
                name_node = current.child_by_field_name("name")
                if name_node:
                    return ast.text_at(name_node)
            elif current.type == "func_literal":
                # Anonymous function (closure)
                parent = current.parent
                # Check if assigned to variable
                if parent and parent.type == "short_var_declaration":
                    left = parent.child_by_field_name("left")
                    if left:
                        # Get first identifier in expression_list
                        for child in left.children:
                            if child.type == "identifier":
                                return ast.text_at(child)
                return "<anonymous>"
            current = current.parent

        return None

    def find_struct_at_line(self, ast: FileAST, line: int) -> Optional[str]:
        """Find the struct name containing a line.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            Struct name or None if not in a struct.
        """
        node = ast.node_at_line(line)
        if node is None:
            return None

        current = node
        while current is not None:
            if current.type == "type_declaration":
                # Look for type_spec child
                for child in current.children:
                    if child.type == "type_spec":
                        name_node = child.child_by_field_name("name")
                        type_node = child.child_by_field_name("type")
                        if name_node and type_node and type_node.type == "struct_type":
                            return ast.text_at(name_node)
            current = current.parent

        return None

    def find_interface_at_line(self, ast: FileAST, line: int) -> Optional[str]:
        """Find the interface name containing a line.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            Interface name or None if not in an interface.
        """
        node = ast.node_at_line(line)
        if node is None:
            return None

        current = node
        while current is not None:
            if current.type == "type_declaration":
                for child in current.children:
                    if child.type == "type_spec":
                        name_node = child.child_by_field_name("name")
                        type_node = child.child_by_field_name("type")
                        if name_node and type_node and type_node.type == "interface_type":
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
            if current.type in ("for_statement", "range_clause"):
                return True
            # Also check for range loops (for ... range)
            if current.type == "for_statement":
                for child in current.children:
                    if child.type == "range_clause":
                        return True
            current = current.parent

        return False

    def get_imports(self, ast: FileAST) -> list[str]:
        """Get all import statements.

        Args:
            ast: The parsed AST.

        Returns:
            List of imported package paths.
        """
        imports = []

        # Find import declarations
        import_nodes = ast.find_nodes_by_type("import_declaration")
        for node in import_nodes:
            # Can be single import or import block
            for child in node.children:
                if child.type == "import_spec":
                    path_node = child.child_by_field_name("path")
                    if path_node:
                        text = ast.text_at(path_node)
                        # Remove quotes
                        if text.startswith('"') or text.startswith('`'):
                            text = text[1:-1]
                        imports.append(text)
                elif child.type == "import_spec_list":
                    for spec in child.children:
                        if spec.type == "import_spec":
                            path_node = spec.child_by_field_name("path")
                            if path_node:
                                text = ast.text_at(path_node)
                                if text.startswith('"') or text.startswith('`'):
                                    text = text[1:-1]
                                imports.append(text)

        return imports

    def get_package_name(self, ast: FileAST) -> Optional[str]:
        """Get the package name from the file.

        Args:
            ast: The parsed AST.

        Returns:
            Package name or None.
        """
        package_nodes = ast.find_nodes_by_type("package_clause")
        if package_nodes:
            for child in package_nodes[0].children:
                if child.type == "package_identifier":
                    return ast.text_at(child)
        return None

    def get_receiver_type(self, ast: FileAST, line: int) -> Optional[str]:
        """Get the receiver type for a method at the given line.

        Args:
            ast: The parsed AST.
            line: Line number (1-indexed).

        Returns:
            Receiver type name or None if not a method.
        """
        node = ast.node_at_line(line)
        if node is None:
            return None

        current = node
        while current is not None:
            if current.type == "method_declaration":
                receiver = current.child_by_field_name("receiver")
                if receiver:
                    # Look for type identifier in parameter_list
                    for child in receiver.children:
                        if child.type == "parameter_declaration":
                            type_node = child.child_by_field_name("type")
                            if type_node:
                                # Handle pointer receivers (*Type)
                                if type_node.type == "pointer_type":
                                    for inner in type_node.children:
                                        if inner.type == "type_identifier":
                                            return ast.text_at(inner)
                                elif type_node.type == "type_identifier":
                                    return ast.text_at(type_node)
                return None
            current = current.parent

        return None
