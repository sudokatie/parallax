"""JSON output formatter for Parallax."""

import json

from parallax import __version__
from parallax.core.types import AnalysisResult
from parallax.output.base import Formatter


class JSONFormatter(Formatter):
    """JSON formatter for machine-readable output."""

    @property
    def name(self) -> str:
        return "json"

    def format(
        self,
        result: AnalysisResult,
        include_suggestions: bool = True,
    ) -> str:
        """Format analysis results as JSON.

        Args:
            result: The analysis result to format.
            include_suggestions: Whether to include fix suggestions.

        Returns:
            Formatted JSON string.
        """
        output = {
            "version": __version__,
            "target": result.target,
            "summary": result.summary,
            "annotations": [],
            "errors": result.errors,
        }

        for annotation in result.annotations:
            ann_dict = annotation.to_dict()
            if not include_suggestions:
                ann_dict.pop("suggestion", None)
            output["annotations"].append(ann_dict)

        return json.dumps(output, indent=2)
