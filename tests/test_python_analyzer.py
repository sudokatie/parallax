"""Tests for Python language analyzer."""

import tempfile
from pathlib import Path

import pytest

from parallax.lang.python import (
    PythonAnalyzer,
    count_complexity,
    find_class_definitions,
    find_f_strings,
    find_function_calls,
    find_function_definitions,
    find_imports,
    find_string_literals,
    get_function_name,
    get_function_parameters,
)


class TestPythonAnalyzer:
    """Tests for PythonAnalyzer class."""

    def test_analyzer_properties(self):
        """Test analyzer name and extensions."""
        analyzer = PythonAnalyzer()
        assert analyzer.name == "python"
        assert analyzer.extensions == {".py", ".pyi"}

    def test_supports_file(self):
        """Test file support checking."""
        analyzer = PythonAnalyzer()
        assert analyzer.supports_file("test.py") is True
        assert analyzer.supports_file("test.pyi") is True
        assert analyzer.supports_file("test.js") is False

    def test_parse_source_simple(self):
        """Test parsing simple Python source."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("x = 1")
        assert ast.root.type == "module"
        assert ast.path == "<string>"

    def test_parse_source_function(self):
        """Test parsing source with function."""
        analyzer = PythonAnalyzer()
        source = """def hello():
    print("hello")
"""
        ast = analyzer.parse_source(source)
        funcs = find_function_definitions(ast)
        assert len(funcs) == 1

    def test_parse_file(self):
        """Test parsing a Python file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1\ny = 2\n")
            f.flush()
            analyzer = PythonAnalyzer()
            ast = analyzer.parse_file(f.name)
            assert ast.path == f.name
            assert ast.root.type == "module"

    def test_parse_file_not_found(self):
        """Test parsing nonexistent file raises error."""
        analyzer = PythonAnalyzer()
        with pytest.raises(FileNotFoundError):
            analyzer.parse_file("/nonexistent/file.py")


class TestFindFunctions:
    """Tests for find_function_definitions helper."""

    def test_find_single_function(self):
        """Test finding a single function."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def foo():
    pass
""")
        funcs = find_function_definitions(ast)
        assert len(funcs) == 1

    def test_find_multiple_functions(self):
        """Test finding multiple functions."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def foo():
    pass

def bar():
    pass

def baz():
    pass
""")
        funcs = find_function_definitions(ast)
        assert len(funcs) == 3

    def test_find_nested_functions(self):
        """Test finding nested functions."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def outer():
    def inner():
        pass
""")
        funcs = find_function_definitions(ast)
        assert len(funcs) == 2

    def test_find_no_functions(self):
        """Test when no functions exist."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("x = 1")
        funcs = find_function_definitions(ast)
        assert len(funcs) == 0


class TestFindClasses:
    """Tests for find_class_definitions helper."""

    def test_find_single_class(self):
        """Test finding a single class."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
class Foo:
    pass
""")
        classes = find_class_definitions(ast)
        assert len(classes) == 1

    def test_find_multiple_classes(self):
        """Test finding multiple classes."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
class Foo:
    pass

class Bar:
    pass
""")
        classes = find_class_definitions(ast)
        assert len(classes) == 2


class TestFindFunctionCalls:
    """Tests for find_function_calls helper."""

    def test_find_all_calls(self):
        """Test finding all function calls."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
print("hello")
len([1, 2, 3])
foo()
""")
        calls = find_function_calls(ast)
        assert len(calls) == 3

    def test_find_calls_by_name(self):
        """Test finding calls by function name."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
print("hello")
print("world")
len([1, 2, 3])
""")
        print_calls = find_function_calls(ast, name="print")
        assert len(print_calls) == 2

    def test_find_method_calls(self):
        """Test finding method calls."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
cursor.execute("SELECT * FROM users")
db.query("SELECT 1")
cursor.execute("SELECT 1")
""")
        execute_calls = find_function_calls(ast, name="execute")
        assert len(execute_calls) == 2


class TestFindStrings:
    """Tests for string finding helpers."""

    def test_find_string_literals(self):
        """Test finding string literals."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
x = "hello"
y = 'world'
z = 42
""")
        strings = find_string_literals(ast)
        assert len(strings) == 2

    def test_find_f_strings(self):
        """Test finding f-strings."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
name = "world"
x = f"hello {name}"
y = "plain string"
z = f'another {name}'
""")
        f_strings = find_f_strings(ast)
        assert len(f_strings) == 2


class TestFindImports:
    """Tests for find_imports helper."""

    def test_find_import_statement(self):
        """Test finding import statements."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
import os
import sys
""")
        imports = find_imports(ast)
        assert len(imports) == 2

    def test_find_from_import(self):
        """Test finding from-import statements."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
from os import path
from sys import argv
""")
        imports = find_imports(ast)
        assert len(imports) == 2

    def test_find_mixed_imports(self):
        """Test finding mixed import types."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
import os
from sys import argv
import json
from pathlib import Path
""")
        imports = find_imports(ast)
        assert len(imports) == 4


class TestGetFunctionInfo:
    """Tests for function info helpers."""

    def test_get_function_name(self):
        """Test getting function name."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def my_function():
    pass
""")
        funcs = find_function_definitions(ast)
        name = get_function_name(funcs[0], ast)
        assert name == "my_function"

    def test_get_function_parameters_simple(self):
        """Test getting simple parameters."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def foo(a, b, c):
    pass
""")
        funcs = find_function_definitions(ast)
        params = get_function_parameters(funcs[0], ast)
        assert params == ["a", "b", "c"]

    def test_get_function_parameters_typed(self):
        """Test getting typed parameters."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def foo(a: int, b: str):
    pass
""")
        funcs = find_function_definitions(ast)
        params = get_function_parameters(funcs[0], ast)
        assert "a" in params
        assert "b" in params

    def test_get_function_parameters_default(self):
        """Test getting parameters with defaults."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def foo(a, b=10, c="default"):
    pass
""")
        funcs = find_function_definitions(ast)
        params = get_function_parameters(funcs[0], ast)
        assert "a" in params
        assert "b" in params
        assert "c" in params


class TestCountComplexity:
    """Tests for cyclomatic complexity counting."""

    def test_complexity_simple(self):
        """Test complexity of simple function."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def simple():
    return 1
""")
        funcs = find_function_definitions(ast)
        complexity = count_complexity(funcs[0])
        assert complexity == 1  # Base complexity

    def test_complexity_with_if(self):
        """Test complexity with if statement."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def with_if(x):
    if x > 0:
        return 1
    return 0
""")
        funcs = find_function_definitions(ast)
        complexity = count_complexity(funcs[0])
        assert complexity == 2  # 1 base + 1 if

    def test_complexity_with_elif(self):
        """Test complexity with elif."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def with_elif(x):
    if x > 0:
        return 1
    elif x < 0:
        return -1
    else:
        return 0
""")
        funcs = find_function_definitions(ast)
        complexity = count_complexity(funcs[0])
        assert complexity == 3  # 1 base + 1 if + 1 elif

    def test_complexity_with_loops(self):
        """Test complexity with loops."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def with_loops(items):
    for item in items:
        while True:
            break
""")
        funcs = find_function_definitions(ast)
        complexity = count_complexity(funcs[0])
        assert complexity == 3  # 1 base + 1 for + 1 while

    def test_complexity_with_and_or(self):
        """Test complexity with boolean operators."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def with_boolean(x, y):
    if x > 0 and y > 0:
        return 1
    if x > 0 or y > 0:
        return 2
    return 0
""")
        funcs = find_function_definitions(ast)
        complexity = count_complexity(funcs[0])
        assert complexity >= 4  # 1 base + 2 if + at least 2 boolean ops

    def test_complexity_with_ternary(self):
        """Test complexity with ternary expression."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def with_ternary(x):
    return 1 if x > 0 else 0
""")
        funcs = find_function_definitions(ast)
        complexity = count_complexity(funcs[0])
        assert complexity == 2  # 1 base + 1 ternary

    def test_complexity_with_except(self):
        """Test complexity with try/except."""
        analyzer = PythonAnalyzer()
        ast = analyzer.parse_source("""
def with_except():
    try:
        risky()
    except ValueError:
        pass
    except TypeError:
        pass
""")
        funcs = find_function_definitions(ast)
        complexity = count_complexity(funcs[0])
        assert complexity == 3  # 1 base + 2 except
