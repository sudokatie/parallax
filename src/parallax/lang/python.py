"""Python language analyzer for Parallax."""

from pathlib import Path

import tree_sitter
import tree_sitter_python

from parallax.lang.base import FileAST, LanguageAnalyzer


class PythonAnalyzer(LanguageAnalyzer):
    """Python language analyzer using tree-sitter."""

    def __init__(self) -> None:
        """Initialize the Python analyzer."""
        self._language = tree_sitter.Language(tree_sitter_python.language())
        self._parser = tree_sitter.Parser(self._language)

    @property
    def name(self) -> str:
        return "python"

    @property
    def extensions(self) -> set[str]:
        return {".py", ".pyi"}

    @property
    def language(self) -> tree_sitter.Language:
        """Get the tree-sitter language object."""
        return self._language

    def parse_file(self, path: str) -> FileAST:
        """Parse a Python file.

        Args:
            path: Path to the Python file.

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

    def parse_source(self, source: str, path: str = "<string>") -> FileAST:
        """Parse Python source code.

        Args:
            source: Python source code as string.
            path: Virtual path for the source.

        Returns:
            FileAST for the parsed source.
        """
        source_bytes = source.encode("utf-8")
        tree = self._parser.parse(source_bytes)
        return FileAST(path=path, tree=tree, source=source_bytes)


# Helper functions for common queries


def find_function_definitions(ast: FileAST) -> list[tree_sitter.Node]:
    """Find all function definitions in the AST.

    Args:
        ast: The FileAST to search.

    Returns:
        List of function_definition nodes.
    """
    return ast.find_nodes_by_type("function_definition")


def find_class_definitions(ast: FileAST) -> list[tree_sitter.Node]:
    """Find all class definitions in the AST.

    Args:
        ast: The FileAST to search.

    Returns:
        List of class_definition nodes.
    """
    return ast.find_nodes_by_type("class_definition")


def find_function_calls(ast: FileAST, name: str | None = None) -> list[tree_sitter.Node]:
    """Find function calls in the AST.

    Args:
        ast: The FileAST to search.
        name: Optional function name to filter by.

    Returns:
        List of call nodes.
    """
    calls = ast.find_nodes_by_type("call")
    if name is None:
        return calls

    result = []
    for call in calls:
        # Get the function being called
        func_node = call.child_by_field_name("function")
        if func_node is not None:
            func_text = ast.text_at(func_node)
            # Handle both simple calls (func()) and attribute calls (obj.func())
            if func_text == name or func_text.endswith(f".{name}"):
                result.append(call)
    return result


def find_string_literals(ast: FileAST) -> list[tree_sitter.Node]:
    """Find all string literals in the AST.

    Args:
        ast: The FileAST to search.

    Returns:
        List of string nodes.
    """
    return ast.find_nodes_by_type("string")


def find_f_strings(ast: FileAST) -> list[tree_sitter.Node]:
    """Find all f-strings (formatted string literals) in the AST.

    Args:
        ast: The FileAST to search.

    Returns:
        List of formatted_string nodes (f-strings).
    """
    # In tree-sitter-python, f-strings are interpolation nodes within strings
    strings = ast.find_nodes_by_type("string")
    f_strings = []
    for s in strings:
        # Check if it's an f-string by looking for interpolation children
        for child in s.children:
            if child.type == "interpolation":
                f_strings.append(s)
                break
        # Also check if the string starts with 'f' or 'F'
        text = ast.text_at(s)
        if text.startswith(('f"', "f'", 'F"', "F'", 'rf"', "rf'", 'fr"', "fr'")):
            if s not in f_strings:
                f_strings.append(s)
    return f_strings


def find_imports(ast: FileAST) -> list[tree_sitter.Node]:
    """Find all import statements in the AST.

    Args:
        ast: The FileAST to search.

    Returns:
        List of import_statement and import_from_statement nodes.
    """
    imports = ast.find_nodes_by_type("import_statement")
    imports.extend(ast.find_nodes_by_type("import_from_statement"))
    return imports


def get_function_name(node: tree_sitter.Node, ast: FileAST) -> str | None:
    """Get the name of a function definition.

    Args:
        node: A function_definition node.
        ast: The FileAST containing the node.

    Returns:
        The function name, or None if not found.
    """
    if node.type != "function_definition":
        return None

    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return ast.text_at(name_node)
    return None


def get_function_parameters(node: tree_sitter.Node, ast: FileAST) -> list[str]:
    """Get the parameter names of a function definition.

    Args:
        node: A function_definition node.
        ast: The FileAST containing the node.

    Returns:
        List of parameter names.
    """
    if node.type != "function_definition":
        return []

    params_node = node.child_by_field_name("parameters")
    if params_node is None:
        return []

    params = []
    for child in params_node.children:
        if child.type == "identifier":
            params.append(ast.text_at(child))
        elif child.type in ("default_parameter", "typed_default_parameter"):
            # These have a 'name' field
            name_node = child.child_by_field_name("name")
            if name_node is not None:
                params.append(ast.text_at(name_node))
        elif child.type == "typed_parameter":
            # typed_parameter has identifier as first non-punctuation child
            for subchild in child.children:
                if subchild.type == "identifier":
                    params.append(ast.text_at(subchild))
                    break
    return params


def count_complexity(node: tree_sitter.Node) -> int:
    """Count cyclomatic complexity of a function.

    Counts: if, elif, for, while, and, or, except, with, assert, conditional_expression

    Args:
        node: A function_definition node.

    Returns:
        Cyclomatic complexity count (base 1).
    """
    complexity = 1  # Base complexity

    complexity_nodes = {
        "if_statement",
        "elif_clause",
        "for_statement",
        "while_statement",
        "except_clause",
        "with_statement",
        "assert_statement",
        "conditional_expression",  # Ternary
    }

    boolean_ops = {"and", "or"}

    def visit(n: tree_sitter.Node) -> None:
        nonlocal complexity
        if n.type in complexity_nodes:
            complexity += 1
        elif n.type == "boolean_operator":
            # Check if it's 'and' or 'or'
            for child in n.children:
                if child.type in boolean_ops:
                    complexity += 1
                    break
        for child in n.children:
            visit(child)

    # Only visit children of the function, not nested functions
    for child in node.children:
        if child.type == "block":
            visit(child)

    return complexity
