"""Security lens for Parallax.

Detects common security vulnerabilities in Python code.
"""

from parallax.core.types import Annotation, Location, Severity
from parallax.lang.python import (
    PythonAnalyzer,
    find_f_strings,
    find_function_calls,
    find_string_literals,
)
from parallax.lenses.base import AnalysisContext, Lens, LensRegistry

# Patterns that indicate sensitive variable names
SECRET_PATTERNS = [
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "api_secret",
    "auth_token",
    "access_token",
    "private_key",
    "credential",
    "token",
]

# SQL-related function names
SQL_FUNCTIONS = ["execute", "executemany", "raw", "query"]


@LensRegistry.register
class SecurityLens(Lens):
    """Security vulnerability detection lens."""

    @property
    def name(self) -> str:
        return "security"

    @property
    def description(self) -> str:
        return "Detects common security vulnerabilities like SQL injection, hardcoded secrets, and command injection"

    def analyze(self, context: AnalysisContext) -> list[Annotation]:
        """Analyze code for security issues."""
        annotations: list[Annotation] = []

        for path, ast in context.files.items():
            # Only analyze Python files
            if not path.endswith((".py", ".pyi")):
                continue

            # Check each rule
            annotations.extend(self._check_sql_injection(path, ast, context))
            annotations.extend(self._check_hardcoded_secrets(path, ast, context))
            annotations.extend(self._check_command_injection(path, ast, context))

        return annotations

    def _check_sql_injection(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for SQL injection vulnerabilities."""
        annotations = []

        # Find calls to SQL execution functions
        for func_name in SQL_FUNCTIONS:
            calls = find_function_calls(ast, name=func_name)
            for call in calls:
                # Get the line number
                line = call.start_point[0] + 1  # Convert to 1-indexed

                # Only flag if in changed lines
                if not context.is_line_changed(path, line):
                    continue

                # Check if any argument is an f-string or string concatenation
                args_node = call.child_by_field_name("arguments")
                if args_node is None:
                    continue

                for arg in args_node.children:
                    arg_text = ast.text_at(arg)

                    # Check for f-string
                    if arg_text.startswith(('f"', "f'", 'F"', "F'")):
                        annotations.append(
                            Annotation(
                                lens="security",
                                rule="sql_injection",
                                location=Location(
                                    file=path,
                                    start_line=line,
                                    end_line=call.end_point[0] + 1,
                                ),
                                severity=Severity.HIGH,
                                confidence=0.9,
                                message="SQL query uses f-string interpolation - potential SQL injection risk",
                                suggestion="Use parameterized queries instead: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                                category="injection",
                            )
                        )
                        break

                    # Check for string concatenation with +
                    if "+" in arg_text and ('"' in arg_text or "'" in arg_text):
                        annotations.append(
                            Annotation(
                                lens="security",
                                rule="sql_injection",
                                location=Location(
                                    file=path,
                                    start_line=line,
                                    end_line=call.end_point[0] + 1,
                                ),
                                severity=Severity.HIGH,
                                confidence=0.7,
                                message="SQL query uses string concatenation - potential SQL injection risk",
                                suggestion="Use parameterized queries instead of string concatenation",
                                category="injection",
                            )
                        )
                        break

                    # Check for % formatting
                    if "%" in arg_text and ('"' in arg_text or "'" in arg_text):
                        annotations.append(
                            Annotation(
                                lens="security",
                                rule="sql_injection",
                                location=Location(
                                    file=path,
                                    start_line=line,
                                    end_line=call.end_point[0] + 1,
                                ),
                                severity=Severity.HIGH,
                                confidence=0.7,
                                message="SQL query uses % formatting - potential SQL injection risk",
                                suggestion="Use parameterized queries instead of % formatting",
                                category="injection",
                            )
                        )
                        break

        return annotations

    def _check_hardcoded_secrets(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for hardcoded secrets in code."""
        annotations = []

        # Find all assignment statements
        assignments = ast.find_nodes_by_type("assignment")
        for assign in assignments:
            line = assign.start_point[0] + 1

            # Only flag if in changed lines
            if not context.is_line_changed(path, line):
                continue

            # Get the left side (variable name)
            left = assign.child_by_field_name("left")
            if left is None:
                continue

            var_name = ast.text_at(left).lower()

            # Check if variable name suggests a secret
            is_secret_name = any(pattern in var_name for pattern in SECRET_PATTERNS)
            if not is_secret_name:
                continue

            # Get the right side (value)
            right = assign.child_by_field_name("right")
            if right is None:
                continue

            # Check if it's a string literal (hardcoded value)
            if right.type == "string":
                value = ast.text_at(right)
                # Ignore empty strings and placeholder values
                if value in ('""', "''", '"placeholder"', "'placeholder'", '"changeme"', "'changeme'"):
                    continue

                annotations.append(
                    Annotation(
                        lens="security",
                        rule="hardcoded_secrets",
                        location=Location(
                            file=path,
                            start_line=line,
                            end_line=assign.end_point[0] + 1,
                        ),
                        severity=Severity.HIGH,
                        confidence=0.8,
                        message=f"Hardcoded secret detected in variable '{ast.text_at(left)}'",
                        suggestion="Use environment variables or a secrets manager instead of hardcoding sensitive values",
                        category="secrets",
                    )
                )

        return annotations

    def _check_command_injection(
        self, path: str, ast, context: AnalysisContext
    ) -> list[Annotation]:
        """Check for command injection vulnerabilities."""
        annotations = []

        # Check os.system calls
        system_calls = find_function_calls(ast, name="system")
        for call in system_calls:
            line = call.start_point[0] + 1

            if not context.is_line_changed(path, line):
                continue

            # Check if argument contains variable interpolation
            args_node = call.child_by_field_name("arguments")
            if args_node is None:
                continue

            for arg in args_node.children:
                arg_text = ast.text_at(arg)
                if arg_text.startswith(('f"', "f'", 'F"', "F'")):
                    annotations.append(
                        Annotation(
                            lens="security",
                            rule="command_injection",
                            location=Location(
                                file=path,
                                start_line=line,
                                end_line=call.end_point[0] + 1,
                            ),
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            message="os.system() called with f-string - potential command injection",
                            suggestion="Use subprocess.run() with a list of arguments instead of shell=True",
                            category="injection",
                        )
                    )
                    break

        # Check subprocess calls with shell=True
        subprocess_calls = find_function_calls(ast, name="run")
        subprocess_calls.extend(find_function_calls(ast, name="Popen"))
        subprocess_calls.extend(find_function_calls(ast, name="call"))

        for call in subprocess_calls:
            line = call.start_point[0] + 1

            if not context.is_line_changed(path, line):
                continue

            call_text = ast.text_at(call)

            # Check for shell=True
            if "shell=True" in call_text or "shell = True" in call_text:
                # Check if first argument is a variable or f-string
                args_node = call.child_by_field_name("arguments")
                if args_node:
                    for arg in args_node.children:
                        if arg.type in ("identifier", "string"):
                            arg_text = ast.text_at(arg)
                            if arg_text.startswith(('f"', "f'")) or arg.type == "identifier":
                                annotations.append(
                                    Annotation(
                                        lens="security",
                                        rule="command_injection",
                                        location=Location(
                                            file=path,
                                            start_line=line,
                                            end_line=call.end_point[0] + 1,
                                        ),
                                        severity=Severity.CRITICAL,
                                        confidence=0.85,
                                        message="subprocess called with shell=True and variable input - potential command injection",
                                        suggestion="Use subprocess.run() with a list of arguments and shell=False",
                                        category="injection",
                                    )
                                )
                                break

        return annotations
