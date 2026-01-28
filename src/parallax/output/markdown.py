"""Markdown output formatter for Parallax."""

from parallax.core.types import AnalysisResult, Annotation, Severity
from parallax.output.base import Formatter


class MarkdownFormatter(Formatter):
    """Markdown formatter for PR comments and reports."""

    @property
    def name(self) -> str:
        return "markdown"

    def format(
        self,
        result: AnalysisResult,
        include_suggestions: bool = True,
    ) -> str:
        """Format analysis results as Markdown.

        Args:
            result: The analysis result to format.
            include_suggestions: Whether to include fix suggestions.

        Returns:
            Formatted Markdown string.
        """
        lines: list[str] = []

        # Header
        lines.append("## Parallax Analysis")
        lines.append("")

        if not result.annotations:
            lines.append("No findings.")
            return "\n".join(lines)

        # Summary
        summary = result.summary
        lines.append(f"**{summary['total']} finding(s)** in `{result.target}`")
        lines.append("")

        # Group by lens
        by_lens: dict[str, list[Annotation]] = {}
        for annotation in result.annotations:
            lens = annotation.lens
            if lens not in by_lens:
                by_lens[lens] = []
            by_lens[lens].append(annotation)

        # Output each lens section
        for lens_name in sorted(by_lens.keys()):
            annotations = by_lens[lens_name]
            lines.append(f"### {lens_name.title()} ({len(annotations)} finding{'s' if len(annotations) != 1 else ''})")
            lines.append("")

            # Table header
            if include_suggestions:
                lines.append("| Severity | Rule | Location | Message | Suggestion |")
                lines.append("|----------|------|----------|---------|------------|")
            else:
                lines.append("| Severity | Rule | Location | Message |")
                lines.append("|----------|------|----------|---------|")

            # Sort by severity (highest first), then by file/line
            sorted_annotations = sorted(
                annotations,
                key=lambda a: (
                    -[Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL].index(a.severity),
                    a.location.file,
                    a.location.start_line,
                ),
            )

            for annotation in sorted_annotations:
                lines.append(self._format_table_row(annotation, include_suggestions))

            lines.append("")

        # Errors section
        if result.errors:
            lines.append("### Errors")
            lines.append("")
            for error in result.errors:
                lines.append(f"- {error}")
            lines.append("")

        return "\n".join(lines)

    def _format_table_row(
        self, annotation: Annotation, include_suggestions: bool
    ) -> str:
        """Format a single annotation as a table row."""
        loc = annotation.location
        location_str = f"`{loc.file}:{loc.start_line}`"

        severity_emoji = {
            Severity.CRITICAL: ":red_circle:",
            Severity.HIGH: ":orange_circle:",
            Severity.MEDIUM: ":yellow_circle:",
            Severity.LOW: ":blue_circle:",
            Severity.INFO: ":white_circle:",
        }

        emoji = severity_emoji.get(annotation.severity, "")
        severity_str = f"{emoji} {annotation.severity.value.upper()}"

        # Escape pipe characters in message
        message = annotation.message.replace("|", "\\|")

        if include_suggestions:
            suggestion = (annotation.suggestion or "").replace("|", "\\|")
            return f"| {severity_str} | {annotation.rule} | {location_str} | {message} | {suggestion} |"
        else:
            return f"| {severity_str} | {annotation.rule} | {location_str} | {message} |"
