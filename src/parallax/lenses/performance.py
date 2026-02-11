"""Performance lens for Parallax.

Detects common performance issues in Python code.
"""

from parallax.core.types import Annotation, Location, Severity
from parallax.lang.python import find_function_calls
from parallax.lenses.base import AnalysisContext, Lens, LensRegistry


# ORM query patterns that may indicate N+1
ORM_QUERY_METHODS = ["filter", "get", "all", "objects", "query", "select"]

# Large allocation patterns
LARGE_ALLOC_PATTERNS = [
    ("*", 1000000),  # multiplying by large numbers
    ("range", 1000000),  # large ranges
]


@LensRegistry.register
class PerformanceLens(Lens):
    """Performance issue detection lens."""

    @property
    def name(self) -> str:
        return "performance"

    @property
    def description(self) -> str:
        return "Detects performance issues like N+1 queries, unbounded loops, inefficient patterns"

    def analyze(self, context: AnalysisContext) -> list[Annotation]:
        """Analyze code for performance issues."""
        annotations: list[Annotation] = []

        for path, ast in context.files.items():
            if not path.endswith((".py", ".pyi")):
                continue

            annotations.extend(self._check_n_plus_one(path, ast, context))
            annotations.extend(self._check_string_concat_in_loop(path, ast, context))
            annotations.extend(self._check_list_vs_generator(path, ast, context))
            annotations.extend(self._check_unbounded_loop(path, ast, context))
            annotations.extend(self._check_large_allocation(path, ast, context))
            annotations.extend(self._check_repeated_computation(path, ast, context))

        return annotations

    def _check_n_plus_one(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for potential N+1 query patterns."""
        annotations = []

        # Find for loops
        for_loops = ast.find_nodes_by_type("for_statement")

        for loop in for_loops:
            line = loop.start_point[0] + 1

            if not context.is_line_changed(path, line):
                continue

            # Get the loop body
            body = loop.child_by_field_name("body")
            if body is None:
                continue

            # Look for ORM query calls inside the loop
            loop_text = ast.text_at(body)

            for method in ORM_QUERY_METHODS:
                if f".{method}(" in loop_text:
                    annotations.append(
                        Annotation(
                            lens="performance",
                            rule="n_plus_one",
                            location=Location(
                                file=path,
                                start_line=line,
                                end_line=loop.end_point[0] + 1,
                            ),
                            severity=Severity.HIGH,
                            confidence=0.7,
                            message=f"Potential N+1 query: ORM call '{method}()' inside loop",
                            suggestion="Use prefetch_related(), select_related(), or batch the query outside the loop",
                            category="database",
                        )
                    )
                    break

        return annotations

    def _check_string_concat_in_loop(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for string concatenation inside loops."""
        annotations = []

        for_loops = ast.find_nodes_by_type("for_statement")
        while_loops = ast.find_nodes_by_type("while_statement")
        all_loops = for_loops + while_loops

        for loop in all_loops:
            line = loop.start_point[0] + 1

            if not context.is_line_changed(path, line):
                continue

            body = loop.child_by_field_name("body")
            if body is None:
                continue

            # Find augmented assignments (+=) in the loop body
            aug_assigns = []
            for child in body.children:
                if child.type == "expression_statement":
                    for subchild in child.children:
                        if subchild.type == "augmented_assignment":
                            aug_assigns.append(subchild)
                elif child.type == "augmented_assignment":
                    aug_assigns.append(child)

            for assign in aug_assigns:
                assign_text = ast.text_at(assign)

                # Check for string += with quotes or str variables
                if "+=" in assign_text:
                    # Check right side for string indicators
                    right = assign.child_by_field_name("right")
                    if right:
                        right_text = ast.text_at(right)
                        # String literals or f-strings
                        if (
                            right_text.startswith(('"', "'", 'f"', "f'", 'F"', "F'"))
                            or right.type == "string"
                            or right.type == "concatenated_string"
                        ):
                            annotations.append(
                                Annotation(
                                    lens="performance",
                                    rule="string_concat_loop",
                                    location=Location(
                                        file=path,
                                        start_line=assign.start_point[0] + 1,
                                        end_line=assign.end_point[0] + 1,
                                    ),
                                    severity=Severity.MEDIUM,
                                    confidence=0.8,
                                    message="String concatenation with += in loop creates O(n^2) behavior",
                                    suggestion="Use a list and ''.join(), or use io.StringIO for building strings",
                                    category="algorithm",
                                )
                            )

        return annotations

    def _check_list_vs_generator(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for list comprehensions that could be generators."""
        annotations = []

        # Find function calls that take iterables
        iterable_consumers = ["sum", "max", "min", "any", "all", "set", "frozenset", "tuple"]

        for func_name in iterable_consumers:
            calls = find_function_calls(ast, name=func_name)

            for call in calls:
                line = call.start_point[0] + 1

                if not context.is_line_changed(path, line):
                    continue

                args_node = call.child_by_field_name("arguments")
                if args_node is None:
                    continue

                # Check if first argument is a list comprehension
                for arg in args_node.children:
                    if arg.type == "list_comprehension":
                        annotations.append(
                            Annotation(
                                lens="performance",
                                rule="list_vs_generator",
                                location=Location(
                                    file=path,
                                    start_line=line,
                                    end_line=call.end_point[0] + 1,
                                ),
                                severity=Severity.LOW,
                                confidence=0.9,
                                message=f"List comprehension passed to {func_name}() - consider generator expression",
                                suggestion=f"Use a generator expression: {func_name}(x for x in ...) instead of {func_name}([x for x in ...]) to avoid intermediate list",
                                category="memory",
                            )
                        )
                        break

        return annotations

    def _check_unbounded_loop(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for potentially unbounded loops."""
        annotations = []

        while_loops = ast.find_nodes_by_type("while_statement")

        for loop in while_loops:
            line = loop.start_point[0] + 1

            if not context.is_line_changed(path, line):
                continue

            # Get the condition
            condition = loop.child_by_field_name("condition")
            if condition is None:
                continue

            cond_text = ast.text_at(condition).strip()

            # Check for while True without obvious break
            if cond_text == "True":
                body = loop.child_by_field_name("body")
                body_text = ast.text_at(body) if body else ""

                # Look for break, return, raise, or exit patterns
                has_exit = any(
                    keyword in body_text
                    for keyword in ["break", "return", "raise", "sys.exit", "exit()"]
                )

                if not has_exit:
                    annotations.append(
                        Annotation(
                            lens="performance",
                            rule="unbounded_loop",
                            location=Location(
                                file=path,
                                start_line=line,
                                end_line=loop.end_point[0] + 1,
                            ),
                            severity=Severity.MEDIUM,
                            confidence=0.6,
                            message="while True loop without visible exit condition",
                            suggestion="Ensure loop has a break/return/raise condition to prevent infinite loop",
                            category="control-flow",
                        )
                    )

        return annotations

    def _check_large_allocation(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for potentially large memory allocations."""
        annotations = []

        # Check range() with large values
        range_calls = find_function_calls(ast, name="range")

        for call in range_calls:
            line = call.start_point[0] + 1

            if not context.is_line_changed(path, line):
                continue

            args_node = call.child_by_field_name("arguments")
            if args_node is None:
                continue

            call_text = ast.text_at(call)

            # Check for large numeric literals in range
            for arg in args_node.children:
                if arg.type == "integer":
                    try:
                        value = int(ast.text_at(arg))
                        if value >= 10_000_000:
                            annotations.append(
                                Annotation(
                                    lens="performance",
                                    rule="large_allocation",
                                    location=Location(
                                        file=path,
                                        start_line=line,
                                        end_line=call.end_point[0] + 1,
                                    ),
                                    severity=Severity.MEDIUM,
                                    confidence=0.7,
                                    message=f"Large range({value:,}) may consume significant memory if converted to list",
                                    suggestion="Ensure range is iterated, not converted to list. Consider chunking if needed.",
                                    category="memory",
                                )
                            )
                    except ValueError:
                        pass

        # Check list() wrapping range
        list_calls = find_function_calls(ast, name="list")

        for call in list_calls:
            line = call.start_point[0] + 1

            if not context.is_line_changed(path, line):
                continue

            call_text = ast.text_at(call)

            if "range(" in call_text:
                annotations.append(
                    Annotation(
                        lens="performance",
                        rule="large_allocation",
                        location=Location(
                            file=path,
                            start_line=line,
                            end_line=call.end_point[0] + 1,
                        ),
                        severity=Severity.LOW,
                        confidence=0.6,
                        message="Converting range to list - verify this is necessary",
                        suggestion="Iterate over range directly instead of converting to list unless random access is needed",
                        category="memory",
                    )
                )

        return annotations

    def _check_repeated_computation(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for repeated expensive computations in loops."""
        annotations = []

        # Expensive functions that shouldn't be called repeatedly
        expensive_calls = ["len", "sorted", "list", "dict", "set", "tuple"]

        for_loops = ast.find_nodes_by_type("for_statement")

        for loop in for_loops:
            line = loop.start_point[0] + 1

            if not context.is_line_changed(path, line):
                continue

            # Check the iterable expression
            right = loop.child_by_field_name("right")
            if right is None:
                continue

            right_text = ast.text_at(right)

            # Check if iterating over len() result (common antipattern)
            if right_text.startswith("range(len("):
                annotations.append(
                    Annotation(
                        lens="performance",
                        rule="repeated_computation",
                        location=Location(
                            file=path,
                            start_line=line,
                            end_line=line,
                        ),
                        severity=Severity.LOW,
                        confidence=0.9,
                        message="range(len(x)) pattern - consider using enumerate() or iterating directly",
                        suggestion="Use 'for item in x' or 'for i, item in enumerate(x)' instead",
                        category="idiom",
                    )
                )

        return annotations
