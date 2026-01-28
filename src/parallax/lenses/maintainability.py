"""Maintainability lens for Parallax.

Detects code maintainability issues like complexity, function length,
and magic numbers.
"""

from typing import Any

from parallax.core.types import Annotation, Location, Severity
from parallax.lang.python import (
    PythonAnalyzer,
    count_complexity,
    find_function_definitions,
    get_function_name,
    get_function_parameters,
)
from parallax.lenses.base import AnalysisContext, Lens, LensRegistry


@LensRegistry.register
class MaintainabilityLens(Lens):
    """Code maintainability analysis lens."""

    def __init__(self) -> None:
        """Initialize with default thresholds."""
        self._complexity_threshold = 10
        self._max_function_lines = 50
        self._max_parameters = 5
        self._max_nesting = 4

    @property
    def name(self) -> str:
        return "maintainability"

    @property
    def description(self) -> str:
        return "Detects code maintainability issues like high complexity, long functions, and too many parameters"

    def configure(self, config: dict[str, Any]) -> None:
        """Configure lens thresholds from config.

        Args:
            config: Configuration dictionary with rule settings.
        """
        if "cyclomatic_complexity" in config:
            cc_config = config["cyclomatic_complexity"]
            if isinstance(cc_config, dict) and "threshold" in cc_config:
                self._complexity_threshold = cc_config["threshold"]

        if "function_length" in config:
            fl_config = config["function_length"]
            if isinstance(fl_config, dict) and "max_lines" in fl_config:
                self._max_function_lines = fl_config["max_lines"]

        if "parameter_count" in config:
            pc_config = config["parameter_count"]
            if isinstance(pc_config, dict) and "max_params" in pc_config:
                self._max_parameters = pc_config["max_params"]

        if "deep_nesting" in config:
            dn_config = config["deep_nesting"]
            if isinstance(dn_config, dict) and "max_depth" in dn_config:
                self._max_nesting = dn_config["max_depth"]

    def analyze(self, context: AnalysisContext) -> list[Annotation]:
        """Analyze code for maintainability issues."""
        annotations: list[Annotation] = []

        for path, ast in context.files.items():
            # Only analyze Python files
            if not path.endswith((".py", ".pyi")):
                continue

            annotations.extend(self._check_complexity(path, ast, context))
            annotations.extend(self._check_function_length(path, ast, context))
            annotations.extend(self._check_parameter_count(path, ast, context))
            annotations.extend(self._check_magic_numbers(path, ast, context))

        return annotations

    def _check_complexity(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for high cyclomatic complexity."""
        annotations = []

        functions = find_function_definitions(ast)
        for func in functions:
            line = func.start_point[0] + 1

            # Only flag if function definition is in changed lines
            if not context.is_line_changed(path, line):
                continue

            func_name = get_function_name(func, ast) or "<anonymous>"
            complexity = count_complexity(func)

            if complexity > self._complexity_threshold:
                # Determine severity based on how much over threshold
                ratio = complexity / self._complexity_threshold
                if ratio >= 2.0:
                    severity = Severity.HIGH
                elif ratio >= 1.5:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                annotations.append(
                    Annotation(
                        lens="maintainability",
                        rule="cyclomatic_complexity",
                        location=Location(
                            file=path,
                            start_line=line,
                            end_line=func.end_point[0] + 1,
                        ),
                        severity=severity,
                        confidence=0.9,
                        message=f"Function '{func_name}' has cyclomatic complexity of {complexity} (threshold: {self._complexity_threshold})",
                        suggestion="Extract conditional branches into separate functions to reduce complexity",
                        category="complexity",
                    )
                )

        return annotations

    def _check_function_length(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for overly long functions."""
        annotations = []

        functions = find_function_definitions(ast)
        for func in functions:
            line = func.start_point[0] + 1

            # Only flag if function definition is in changed lines
            if not context.is_line_changed(path, line):
                continue

            func_name = get_function_name(func, ast) or "<anonymous>"
            func_lines = func.end_point[0] - func.start_point[0] + 1

            if func_lines > self._max_function_lines:
                # Determine severity based on how much over threshold
                ratio = func_lines / self._max_function_lines
                if ratio >= 2.0:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                annotations.append(
                    Annotation(
                        lens="maintainability",
                        rule="function_length",
                        location=Location(
                            file=path,
                            start_line=line,
                            end_line=func.end_point[0] + 1,
                        ),
                        severity=severity,
                        confidence=0.85,
                        message=f"Function '{func_name}' is {func_lines} lines long (threshold: {self._max_function_lines})",
                        suggestion="Break down into smaller, focused functions",
                        category="complexity",
                    )
                )

        return annotations

    def _check_parameter_count(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for functions with too many parameters."""
        annotations = []

        functions = find_function_definitions(ast)
        for func in functions:
            line = func.start_point[0] + 1

            # Only flag if function definition is in changed lines
            if not context.is_line_changed(path, line):
                continue

            func_name = get_function_name(func, ast) or "<anonymous>"
            params = get_function_parameters(func, ast)

            # Don't count 'self' or 'cls'
            param_count = len([p for p in params if p not in ("self", "cls")])

            if param_count > self._max_parameters:
                annotations.append(
                    Annotation(
                        lens="maintainability",
                        rule="parameter_count",
                        location=Location(
                            file=path,
                            start_line=line,
                            end_line=line,
                        ),
                        severity=Severity.LOW,
                        confidence=0.8,
                        message=f"Function '{func_name}' has {param_count} parameters (threshold: {self._max_parameters})",
                        suggestion="Consider using a data class or configuration object to group related parameters",
                        category="design",
                    )
                )

        return annotations

    def _check_magic_numbers(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for magic numbers in code."""
        annotations = []

        # Find all integer and float literals
        numbers = ast.find_nodes_by_type("integer")
        numbers.extend(ast.find_nodes_by_type("float"))

        # Common acceptable values
        acceptable = {
            "0", "1", "-1", "2", "0.0", "1.0", "0.5", "100", "1000",
            "60", "24", "365", "3600", "86400",  # Time constants
            "10", "16", "256", "1024",  # Common bases/sizes
        }

        for num in numbers:
            line = num.start_point[0] + 1

            # Only flag if in changed lines
            if not context.is_line_changed(path, line):
                continue

            value = ast.text_at(num)

            # Skip acceptable values
            if value in acceptable:
                continue

            # Skip if it's part of a constant assignment (UPPER_CASE)
            parent = num.parent
            if parent and parent.type == "assignment":
                left = parent.child_by_field_name("left")
                if left:
                    var_name = ast.text_at(left)
                    if var_name.isupper() or var_name.startswith("_"):
                        continue

            # Skip if it's an index or simple comparison
            if parent and parent.type in ("subscript", "slice"):
                continue

            annotations.append(
                Annotation(
                    lens="maintainability",
                    rule="magic_number",
                    location=Location(
                        file=path,
                        start_line=line,
                        end_line=line,
                    ),
                    severity=Severity.INFO,
                    confidence=0.6,
                    message=f"Magic number {value} should be a named constant",
                    suggestion=f"Define a constant: MEANINGFUL_NAME = {value}",
                    category="readability",
                )
            )

        return annotations
