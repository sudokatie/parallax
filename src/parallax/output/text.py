"""Text output formatter for Parallax."""

from parallax.core.types import AnalysisResult, Annotation, Severity
from parallax.output.base import Formatter


# ANSI color codes
COLORS = {
    Severity.CRITICAL: "\033[91m",  # Red
    Severity.HIGH: "\033[91m",  # Red
    Severity.MEDIUM: "\033[93m",  # Yellow
    Severity.LOW: "\033[94m",  # Blue
    Severity.INFO: "\033[90m",  # Gray
}
RESET = "\033[0m"
BOLD = "\033[1m"


class TextFormatter(Formatter):
    """Human-readable text formatter for terminal output."""

    @property
    def name(self) -> str:
        return "text"

    def format(
        self,
        result: AnalysisResult,
        include_suggestions: bool = True,
    ) -> str:
        """Format analysis results as human-readable text.

        Args:
            result: The analysis result to format.
            include_suggestions: Whether to include fix suggestions.

        Returns:
            Formatted text output.
        """
        lines: list[str] = []

        # Header
        lines.append(f"{BOLD}Parallax Analysis{RESET}")
        lines.append(f"Target: {result.target}")
        lines.append("")

        if not result.annotations:
            lines.append("No findings.")
            return "\n".join(lines)

        # Summary
        summary = result.summary
        lines.append(f"Found {summary['total']} finding(s):")

        # By severity
        by_sev = summary["by_severity"]
        sev_parts = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = by_sev.get(sev.value, 0)
            if count > 0:
                color = COLORS.get(sev, "")
                sev_parts.append(f"{color}{count} {sev.value}{RESET}")
        if sev_parts:
            lines.append("  " + ", ".join(sev_parts))

        lines.append("")

        # Group by file
        by_file: dict[str, list[Annotation]] = {}
        for annotation in result.annotations:
            path = annotation.location.file
            if path not in by_file:
                by_file[path] = []
            by_file[path].append(annotation)

        # Sort files and annotations
        for path in sorted(by_file.keys()):
            lines.append(f"{BOLD}{path}{RESET}")
            annotations = sorted(by_file[path], key=lambda a: a.location.start_line)

            for annotation in annotations:
                lines.append(self._format_annotation(annotation, include_suggestions))
                lines.append("")

        # Errors
        if result.errors:
            lines.append(f"{COLORS[Severity.HIGH]}Errors:{RESET}")
            for error in result.errors:
                lines.append(f"  - {error}")

        return "\n".join(lines)

    def _format_annotation(
        self, annotation: Annotation, include_suggestions: bool
    ) -> str:
        """Format a single annotation."""
        lines: list[str] = []

        # Header line: rule [SEVERITY] location
        color = COLORS.get(annotation.severity, "")
        loc = annotation.location
        location_str = f"{loc.start_line}"
        if loc.start_column is not None:
            location_str += f":{loc.start_column}"

        rule_id = f"{annotation.lens}/{annotation.rule}"
        lines.append(
            f"  {rule_id} {color}[{annotation.severity.value.upper()}]{RESET} "
            f"line {location_str}"
        )

        # Message
        lines.append(f"    {annotation.message}")

        # Suggestion
        if include_suggestions and annotation.suggestion:
            lines.append(f"    {BOLD}Suggestion:{RESET} {annotation.suggestion}")

        # Doc URL
        if annotation.doc_url:
            lines.append(f"    Docs: {annotation.doc_url}")

        return "\n".join(lines)
