"""Tests for JavaScript/TypeScript analyzer."""

import pytest

from parallax.lang import JavaScriptAnalyzer, TypeScriptAnalyzer


class TestJavaScriptAnalyzerBasics:
    """Test basic JavaScript analyzer functionality."""

    def test_analyzer_properties(self):
        """Test analyzer name and extensions."""
        analyzer = JavaScriptAnalyzer()
        assert analyzer.name == "javascript"
        assert ".js" in analyzer.extensions
        assert ".jsx" in analyzer.extensions
        assert ".mjs" in analyzer.extensions
        assert ".cjs" in analyzer.extensions

    def test_parse_source(self):
        """Test parsing JavaScript source code."""
        analyzer = JavaScriptAnalyzer()
        source = """
function hello(name) {
    return "Hello, " + name;
}
"""
        ast = analyzer.parse_source(source)
        assert ast is not None
        assert ast.tree is not None


class TestJavaScriptFunctionDetection:
    """Test function detection in JavaScript."""

    def test_find_function_declaration(self):
        """Test finding function declarations."""
        analyzer = JavaScriptAnalyzer()
        source = """
function greet(name) {
    console.log("Hello, " + name);
}
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 3)
        assert func_name == "greet"

    def test_find_arrow_function_assigned(self):
        """Test finding arrow functions assigned to variables."""
        analyzer = JavaScriptAnalyzer()
        source = """
const greet = (name) => {
    console.log("Hello, " + name);
};
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 3)
        assert func_name == "greet"

    def test_find_method_definition(self):
        """Test finding class method definitions."""
        analyzer = JavaScriptAnalyzer()
        source = """
class Greeter {
    greet(name) {
        console.log("Hello, " + name);
    }
}
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 4)
        assert func_name == "greet"

    def test_not_in_function(self):
        """Test when line is not in a function."""
        analyzer = JavaScriptAnalyzer()
        source = """
const x = 1;
const y = 2;
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 2)
        assert func_name is None


class TestJavaScriptClassDetection:
    """Test class detection in JavaScript."""

    def test_find_class(self):
        """Test finding class declarations."""
        analyzer = JavaScriptAnalyzer()
        source = """
class Greeter {
    constructor(name) {
        this.name = name;
    }
}
"""
        ast = analyzer.parse_source(source)
        class_name = analyzer.find_class_at_line(ast, 3)
        assert class_name == "Greeter"

    def test_not_in_class(self):
        """Test when line is not in a class."""
        analyzer = JavaScriptAnalyzer()
        source = """
function standalone() {
    return 1;
}
"""
        ast = analyzer.parse_source(source)
        class_name = analyzer.find_class_at_line(ast, 2)
        assert class_name is None


class TestJavaScriptLoopDetection:
    """Test loop detection in JavaScript."""

    def test_in_for_loop(self):
        """Test detecting code in a for loop."""
        analyzer = JavaScriptAnalyzer()
        source = """
for (let i = 0; i < 10; i++) {
    console.log(i);
}
"""
        ast = analyzer.parse_source(source)
        assert analyzer.is_in_loop(ast, 3) is True

    def test_in_while_loop(self):
        """Test detecting code in a while loop."""
        analyzer = JavaScriptAnalyzer()
        source = """
while (true) {
    console.log("loop");
}
"""
        ast = analyzer.parse_source(source)
        assert analyzer.is_in_loop(ast, 3) is True

    def test_in_for_of_loop(self):
        """Test detecting code in a for-of loop."""
        analyzer = JavaScriptAnalyzer()
        source = """
for (const item of items) {
    console.log(item);
}
"""
        ast = analyzer.parse_source(source)
        assert analyzer.is_in_loop(ast, 3) is True

    def test_not_in_loop(self):
        """Test when code is not in a loop."""
        analyzer = JavaScriptAnalyzer()
        source = """
function test() {
    return 1;
}
"""
        ast = analyzer.parse_source(source)
        assert analyzer.is_in_loop(ast, 3) is False


class TestJavaScriptImports:
    """Test import detection in JavaScript."""

    def test_es6_imports(self):
        """Test detecting ES6 imports."""
        analyzer = JavaScriptAnalyzer()
        source = """
import React from 'react';
import { useState } from 'react';

function App() {
    return null;
}
"""
        ast = analyzer.parse_source(source)
        imports = analyzer.get_imports(ast)
        assert "react" in imports

    def test_require_calls(self):
        """Test detecting require calls."""
        analyzer = JavaScriptAnalyzer()
        source = """
const fs = require('fs');
const path = require('path');
"""
        ast = analyzer.parse_source(source)
        imports = analyzer.get_imports(ast)
        assert "fs" in imports
        assert "path" in imports


class TestTypeScriptAnalyzerBasics:
    """Test basic TypeScript analyzer functionality."""

    def test_analyzer_properties(self):
        """Test analyzer name and extensions."""
        analyzer = TypeScriptAnalyzer()
        assert analyzer.name == "typescript"
        assert ".ts" in analyzer.extensions
        assert ".tsx" in analyzer.extensions
        assert ".mts" in analyzer.extensions

    def test_parse_source(self):
        """Test parsing TypeScript source code."""
        analyzer = TypeScriptAnalyzer()
        source = """
function hello(name: string): string {
    return "Hello, " + name;
}
"""
        ast = analyzer.parse_source(source)
        assert ast is not None
        assert ast.tree is not None


class TestTypeScriptFunctionDetection:
    """Test function detection in TypeScript."""

    def test_find_typed_function(self):
        """Test finding typed function declarations."""
        analyzer = TypeScriptAnalyzer()
        source = """
function greet(name: string): void {
    console.log("Hello, " + name);
}
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 3)
        assert func_name == "greet"

    def test_find_typed_arrow_function(self):
        """Test finding typed arrow functions."""
        analyzer = TypeScriptAnalyzer()
        source = """
const greet = (name: string): void => {
    console.log("Hello, " + name);
};
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 3)
        assert func_name == "greet"


class TestTypeScriptImports:
    """Test import detection in TypeScript."""

    def test_typed_imports(self):
        """Test detecting TypeScript imports."""
        analyzer = TypeScriptAnalyzer()
        source = """
import type { User } from './types';
import { useState } from 'react';

const user: User = { name: "test" };
"""
        ast = analyzer.parse_source(source)
        imports = analyzer.get_imports(ast)
        assert "./types" in imports
        assert "react" in imports


class TestTypeScriptTypeAnnotations:
    """Test type annotation detection in TypeScript."""

    def test_get_type_annotation(self):
        """Test getting type annotations."""
        analyzer = TypeScriptAnalyzer()
        source = """
const name: string = "test";
"""
        ast = analyzer.parse_source(source)
        type_ann = analyzer.get_type_annotations(ast, 2)
        # Type annotation includes the colon
        assert type_ann is not None
        assert "string" in type_ann
