"""Tests for Go analyzer."""

import pytest

from parallax.lang.go import GoAnalyzer


class TestGoAnalyzerBasics:
    """Test basic Go analyzer functionality."""

    def test_analyzer_properties(self):
        """Test analyzer name and extensions."""
        analyzer = GoAnalyzer()
        assert analyzer.name == "go"
        assert ".go" in analyzer.extensions

    def test_parse_source(self):
        """Test parsing Go source code."""
        analyzer = GoAnalyzer()
        source = """
package main

func hello(name string) string {
    return "Hello, " + name
}
"""
        ast = analyzer.parse_source(source)
        assert ast is not None
        assert ast.tree is not None


class TestGoFunctionDetection:
    """Test function detection in Go."""

    def test_find_function_declaration(self):
        """Test finding function declarations."""
        analyzer = GoAnalyzer()
        source = """
package main

func greet(name string) {
    fmt.Println("Hello, " + name)
}
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 5)
        assert func_name == "greet"

    def test_find_method_declaration(self):
        """Test finding method declarations."""
        analyzer = GoAnalyzer()
        source = """
package main

type Greeter struct {
    prefix string
}

func (g *Greeter) Greet(name string) {
    fmt.Println(g.prefix + name)
}
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 9)
        assert func_name == "Greet"

    def test_not_in_function(self):
        """Test when line is not in a function."""
        analyzer = GoAnalyzer()
        source = """
package main

var x = 1
var y = 2
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 4)
        assert func_name is None

    def test_find_main_function(self):
        """Test finding main function."""
        analyzer = GoAnalyzer()
        source = """
package main

func main() {
    fmt.Println("Hello")
}
"""
        ast = analyzer.parse_source(source)
        func_name = analyzer.find_function_at_line(ast, 5)
        assert func_name == "main"


class TestGoStructDetection:
    """Test struct detection in Go."""

    def test_find_struct(self):
        """Test finding struct declarations."""
        analyzer = GoAnalyzer()
        source = """
package main

type User struct {
    Name string
    Age  int
}
"""
        ast = analyzer.parse_source(source)
        struct_name = analyzer.find_struct_at_line(ast, 5)
        assert struct_name == "User"

    def test_not_in_struct(self):
        """Test when line is not in a struct."""
        analyzer = GoAnalyzer()
        source = """
package main

func standalone() int {
    return 1
}
"""
        ast = analyzer.parse_source(source)
        struct_name = analyzer.find_struct_at_line(ast, 5)
        assert struct_name is None


class TestGoInterfaceDetection:
    """Test interface detection in Go."""

    def test_find_interface(self):
        """Test finding interface declarations."""
        analyzer = GoAnalyzer()
        source = """
package main

type Reader interface {
    Read(p []byte) (n int, err error)
}
"""
        ast = analyzer.parse_source(source)
        iface_name = analyzer.find_interface_at_line(ast, 5)
        assert iface_name == "Reader"


class TestGoLoopDetection:
    """Test loop detection in Go."""

    def test_in_for_loop(self):
        """Test detecting code in a for loop."""
        analyzer = GoAnalyzer()
        source = """
package main

func test() {
    for i := 0; i < 10; i++ {
        fmt.Println(i)
    }
}
"""
        ast = analyzer.parse_source(source)
        assert analyzer.is_in_loop(ast, 6) is True

    def test_in_range_loop(self):
        """Test detecting code in a range loop."""
        analyzer = GoAnalyzer()
        source = """
package main

func test() {
    for _, item := range items {
        fmt.Println(item)
    }
}
"""
        ast = analyzer.parse_source(source)
        assert analyzer.is_in_loop(ast, 6) is True

    def test_in_infinite_loop(self):
        """Test detecting code in an infinite loop."""
        analyzer = GoAnalyzer()
        source = """
package main

func test() {
    for {
        fmt.Println("loop")
    }
}
"""
        ast = analyzer.parse_source(source)
        assert analyzer.is_in_loop(ast, 6) is True

    def test_not_in_loop(self):
        """Test when code is not in a loop."""
        analyzer = GoAnalyzer()
        source = """
package main

func test() {
    return 1
}
"""
        ast = analyzer.parse_source(source)
        assert analyzer.is_in_loop(ast, 5) is False


class TestGoImports:
    """Test import detection in Go."""

    def test_single_import(self):
        """Test detecting single imports."""
        analyzer = GoAnalyzer()
        source = """
package main

import "fmt"

func main() {
    fmt.Println("Hello")
}
"""
        ast = analyzer.parse_source(source)
        imports = analyzer.get_imports(ast)
        assert "fmt" in imports

    def test_import_block(self):
        """Test detecting import blocks."""
        analyzer = GoAnalyzer()
        source = """
package main

import (
    "fmt"
    "os"
    "strings"
)

func main() {
    fmt.Println("Hello")
}
"""
        ast = analyzer.parse_source(source)
        imports = analyzer.get_imports(ast)
        assert "fmt" in imports
        assert "os" in imports
        assert "strings" in imports

    def test_aliased_import(self):
        """Test detecting aliased imports."""
        analyzer = GoAnalyzer()
        source = """
package main

import (
    f "fmt"
    . "math"
)
"""
        ast = analyzer.parse_source(source)
        imports = analyzer.get_imports(ast)
        assert "fmt" in imports
        assert "math" in imports


class TestGoPackage:
    """Test package detection in Go."""

    def test_get_package_name(self):
        """Test getting package name."""
        analyzer = GoAnalyzer()
        source = """
package mypackage

func Test() {}
"""
        ast = analyzer.parse_source(source)
        pkg = analyzer.get_package_name(ast)
        assert pkg == "mypackage"

    def test_main_package(self):
        """Test getting main package."""
        analyzer = GoAnalyzer()
        source = """
package main

func main() {}
"""
        ast = analyzer.parse_source(source)
        pkg = analyzer.get_package_name(ast)
        assert pkg == "main"


class TestGoReceiverType:
    """Test method receiver type detection in Go."""

    def test_pointer_receiver(self):
        """Test getting pointer receiver type."""
        analyzer = GoAnalyzer()
        source = """
package main

type Server struct{}

func (s *Server) Start() {
    fmt.Println("Starting")
}
"""
        ast = analyzer.parse_source(source)
        receiver = analyzer.get_receiver_type(ast, 7)
        assert receiver == "Server"

    def test_value_receiver(self):
        """Test getting value receiver type."""
        analyzer = GoAnalyzer()
        source = """
package main

type Point struct {
    X, Y int
}

func (p Point) String() string {
    return fmt.Sprintf("(%d, %d)", p.X, p.Y)
}
"""
        ast = analyzer.parse_source(source)
        receiver = analyzer.get_receiver_type(ast, 9)
        assert receiver == "Point"

    def test_not_a_method(self):
        """Test when function is not a method."""
        analyzer = GoAnalyzer()
        source = """
package main

func standalone() {
    return
}
"""
        ast = analyzer.parse_source(source)
        receiver = analyzer.get_receiver_type(ast, 5)
        assert receiver is None
