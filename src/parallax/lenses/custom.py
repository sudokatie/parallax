"""Custom lens framework for user-defined lenses.

Allows users to define lenses via YAML/TOML configuration files.
Lenses can be placed in ~/.config/parallax/lenses/ or specified via config.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from parallax.core.types import Annotation, Location, Severity
from parallax.lenses.base import AnalysisContext, Lens


@dataclass
class PatternRule:
    """A pattern-based detection rule.

    Matches code using regex patterns and tree-sitter queries.
    """

    name: str
    pattern: str
    pattern_type: str  # "regex" or "tree-sitter"
    message: str
    severity: Severity
    confidence: float = 0.8
    suggestion: str | None = None
    doc_url: str | None = None
    file_patterns: list[str] | None = None  # Glob patterns for files to check
    exclude_patterns: list[str] | None = None  # Patterns to exclude matches

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> "PatternRule":
        """Create a PatternRule from a dictionary.

        Args:
            name: Rule name.
            data: Rule configuration dictionary.

        Returns:
            PatternRule instance.
        """
        severity_str = data.get("severity", "medium").lower()
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity = severity_map.get(severity_str, Severity.MEDIUM)

        return cls(
            name=name,
            pattern=data["pattern"],
            pattern_type=data.get("type", "regex"),
            message=data["message"],
            severity=severity,
            confidence=data.get("confidence", 0.8),
            suggestion=data.get("suggestion"),
            doc_url=data.get("doc_url"),
            file_patterns=data.get("files"),
            exclude_patterns=data.get("exclude"),
        )


@dataclass
class CustomLensDefinition:
    """Definition of a custom lens loaded from YAML/TOML.

    Contains metadata and rules for the custom lens.
    """

    name: str
    description: str
    version: str
    rules: list[PatternRule]
    author: str | None = None
    category: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CustomLensDefinition":
        """Create a CustomLensDefinition from a dictionary.

        Args:
            data: Lens definition dictionary.

        Returns:
            CustomLensDefinition instance.
        """
        rules_data = data.get("rules", {})
        rules = [
            PatternRule.from_dict(name, rule_data)
            for name, rule_data in rules_data.items()
        ]

        return cls(
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "0.1.0"),
            rules=rules,
            author=data.get("author"),
            category=data.get("category"),
        )

    @classmethod
    def load(cls, path: Path) -> "CustomLensDefinition":
        """Load a custom lens definition from a YAML file.

        Args:
            path: Path to the YAML file.

        Returns:
            CustomLensDefinition instance.

        Raises:
            ValueError: If the file cannot be parsed or is invalid.
        """
        with open(path) as f:
            data = yaml.safe_load(f)

        if not data:
            raise ValueError(f"Empty lens definition: {path}")

        if "name" not in data:
            raise ValueError(f"Missing 'name' in lens definition: {path}")

        return cls.from_dict(data)


class CustomLens(Lens):
    """A lens created from a custom definition.

    Applies pattern-based rules to detect code issues.
    """

    def __init__(self, definition: CustomLensDefinition):
        """Initialize from a custom lens definition.

        Args:
            definition: The custom lens definition.
        """
        self._definition = definition
        self._compiled_patterns: dict[str, re.Pattern] = {}

        # Pre-compile regex patterns
        for rule in definition.rules:
            if rule.pattern_type == "regex":
                try:
                    self._compiled_patterns[rule.name] = re.compile(
                        rule.pattern, re.MULTILINE
                    )
                except re.error as e:
                    raise ValueError(
                        f"Invalid regex pattern in rule '{rule.name}': {e}"
                    )

    @property
    def name(self) -> str:
        """Return the lens name."""
        return self._definition.name

    @property
    def description(self) -> str:
        """Return the lens description."""
        return self._definition.description

    def analyze(self, context: AnalysisContext) -> list[Annotation]:
        """Analyze code using pattern-based rules.

        Args:
            context: The analysis context.

        Returns:
            List of annotations from matched patterns.
        """
        annotations = []

        for file_diff in context.diff.files:
            path = file_diff.new_path or file_diff.old_path
            if not path:
                continue

            file_ast = context.get_file(path)
            if not file_ast:
                continue

            source = file_ast.source.decode("utf-8", errors="replace")

            for rule in self._definition.rules:
                # Check file pattern filter
                if rule.file_patterns:
                    if not self._matches_any_pattern(path, rule.file_patterns):
                        continue

                # Apply rule
                rule_annotations = self._apply_rule(
                    rule, path, source, context
                )
                annotations.extend(rule_annotations)

        return annotations

    def _matches_any_pattern(self, path: str, patterns: list[str]) -> bool:
        """Check if a path matches any of the given glob patterns.

        Args:
            path: File path.
            patterns: List of glob patterns.

        Returns:
            True if path matches any pattern.
        """
        from fnmatch import fnmatch

        return any(fnmatch(path, pattern) for pattern in patterns)

    def _apply_rule(
        self,
        rule: PatternRule,
        path: str,
        source: str,
        context: AnalysisContext,
    ) -> list[Annotation]:
        """Apply a single rule to source code.

        Args:
            rule: The rule to apply.
            path: File path.
            source: Source code content.
            context: Analysis context.

        Returns:
            List of annotations from matches.
        """
        annotations = []

        if rule.pattern_type == "regex":
            compiled = self._compiled_patterns.get(rule.name)
            if not compiled:
                return []

            for match in compiled.finditer(source):
                # Calculate line number from match position
                line = source[:match.start()].count("\n") + 1

                # Only flag if line is in the diff
                if not context.is_line_changed(path, line):
                    continue

                # Check exclude patterns
                if rule.exclude_patterns:
                    matched_text = match.group(0)
                    if any(
                        re.search(excl, matched_text)
                        for excl in rule.exclude_patterns
                    ):
                        continue

                annotations.append(
                    Annotation(
                        lens=self.name,
                        rule=rule.name,
                        location=Location(
                            file=path,
                            start_line=line,
                            end_line=line,
                        ),
                        severity=rule.severity,
                        confidence=rule.confidence,
                        message=rule.message,
                        suggestion=rule.suggestion,
                        doc_url=rule.doc_url,
                    )
                )

        elif rule.pattern_type == "tree-sitter":
            file_ast = context.get_file(path)
            if file_ast:
                try:
                    nodes = file_ast.query(rule.pattern)
                    for node in nodes:
                        line = node.start_point[0] + 1

                        if not context.is_line_changed(path, line):
                            continue

                        annotations.append(
                            Annotation(
                                lens=self.name,
                                rule=rule.name,
                                location=Location(
                                    file=path,
                                    start_line=line,
                                    end_line=node.end_point[0] + 1,
                                    start_column=node.start_point[1],
                                    end_column=node.end_point[1],
                                ),
                                severity=rule.severity,
                                confidence=rule.confidence,
                                message=rule.message,
                                suggestion=rule.suggestion,
                                doc_url=rule.doc_url,
                            )
                        )
                except Exception:
                    # Invalid tree-sitter query, skip silently
                    pass

        return annotations


class CustomLensLoader:
    """Loads custom lenses from user configuration directories.

    Searches for lens definitions in:
    - ~/.config/parallax/lenses/
    - .parallax/lenses/ (project-local)
    - Paths specified in config
    """

    DEFAULT_DIRS = [
        Path.home() / ".config" / "parallax" / "lenses",
        Path(".parallax") / "lenses",
    ]

    def __init__(self, extra_dirs: list[Path] | None = None):
        """Initialize the loader.

        Args:
            extra_dirs: Additional directories to search for lenses.
        """
        self._dirs = list(self.DEFAULT_DIRS)
        if extra_dirs:
            self._dirs.extend(extra_dirs)

    def discover(self) -> list[Path]:
        """Discover all custom lens definition files.

        Returns:
            List of paths to lens definition files.
        """
        lens_files = []

        for lens_dir in self._dirs:
            if not lens_dir.exists():
                continue

            for file_path in lens_dir.glob("*.yaml"):
                lens_files.append(file_path)

            for file_path in lens_dir.glob("*.yml"):
                lens_files.append(file_path)

        return lens_files

    def load_all(self) -> list[CustomLens]:
        """Load all discovered custom lenses.

        Returns:
            List of CustomLens instances.
        """
        lenses = []

        for path in self.discover():
            try:
                definition = CustomLensDefinition.load(path)
                lens = CustomLens(definition)
                lenses.append(lens)
            except Exception:
                # Skip invalid lens definitions
                pass

        return lenses

    def load(self, path: Path) -> CustomLens:
        """Load a specific custom lens.

        Args:
            path: Path to the lens definition file.

        Returns:
            CustomLens instance.

        Raises:
            ValueError: If the lens cannot be loaded.
        """
        definition = CustomLensDefinition.load(path)
        return CustomLens(definition)


def create_example_lens() -> str:
    """Generate an example custom lens definition.

    Returns:
        YAML string for an example lens.
    """
    return """# Custom Lens Definition
# Place this file in ~/.config/parallax/lenses/

name: my-company
description: Company-specific code standards
version: "1.0.0"
author: Your Name
category: standards

rules:
  deprecated-import:
    pattern: "from\\\\s+old_module\\\\s+import"
    type: regex
    message: "old_module is deprecated, use new_module instead"
    severity: medium
    confidence: 0.9
    suggestion: "Replace 'from old_module import X' with 'from new_module import X'"
    files:
      - "*.py"

  no-print-debug:
    pattern: "print\\\\s*\\\\(.*debug"
    type: regex
    message: "Debug print statements should be removed"
    severity: low
    confidence: 0.7
    suggestion: "Use logging instead of print for debug output"
    exclude:
      - "# noqa"
      - "# allowed"

  long-function:
    pattern: "(function_definition) @fn"
    type: tree-sitter
    message: "Function may be too long - consider refactoring"
    severity: info
    confidence: 0.6
    files:
      - "*.py"
"""
