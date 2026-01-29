"""SARIF output formatter for Parallax.

SARIF (Static Analysis Results Interchange Format) is a standard format
for the output of static analysis tools, designed for CI/CD integration.
"""

import json
from typing import Any

from parallax import __version__
from parallax.core.types import AnalysisResult, Annotation, Severity
from parallax.output.base import Formatter

# Map Parallax severity to SARIF level
SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SARIFFormatter(Formatter):
    """SARIF v2.1.0 formatter for CI integration."""

    @property
    def name(self) -> str:
        return "sarif"

    def format(
        self,
        result: AnalysisResult,
        include_suggestions: bool = True,
    ) -> str:
        """Format analysis results as SARIF.

        Args:
            result: The analysis result to format.
            include_suggestions: Whether to include fix suggestions.

        Returns:
            Formatted SARIF JSON string.
        """
        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Parallax",
                            "version": __version__,
                            "informationUri": "https://github.com/katieblackabee/parallax",
                            "rules": self._build_rules(result.annotations),
                        }
                    },
                    "results": self._build_results(result.annotations, include_suggestions),
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def _build_rules(self, annotations: list[Annotation]) -> list[dict[str, Any]]:
        """Build SARIF rules array from annotations."""
        seen_rules: dict[str, dict[str, Any]] = {}

        for annotation in annotations:
            rule_id = f"{annotation.lens}/{annotation.rule}"
            if rule_id in seen_rules:
                continue

            rule: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": annotation.rule.replace("_", " ").title()},
            }

            if annotation.doc_url:
                rule["helpUri"] = annotation.doc_url

            # Default configuration
            rule["defaultConfiguration"] = {
                "level": SARIF_LEVELS.get(annotation.severity, "warning")
            }

            seen_rules[rule_id] = rule

        return list(seen_rules.values())

    def _build_results(
        self, annotations: list[Annotation], include_suggestions: bool
    ) -> list[dict[str, Any]]:
        """Build SARIF results array from annotations."""
        results = []

        for annotation in annotations:
            rule_id = f"{annotation.lens}/{annotation.rule}"
            loc = annotation.location

            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": SARIF_LEVELS.get(annotation.severity, "warning"),
                "message": {
                    "text": annotation.message,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": loc.file,
                            },
                            "region": {
                                "startLine": loc.start_line,
                                "endLine": loc.end_line,
                            },
                        }
                    }
                ],
                "properties": {
                    "confidence": annotation.confidence,
                },
            }

            # Add column info if available
            if loc.start_column is not None:
                result["locations"][0]["physicalLocation"]["region"][
                    "startColumn"
                ] = loc.start_column
            if loc.end_column is not None:
                result["locations"][0]["physicalLocation"]["region"]["endColumn"] = loc.end_column

            # Add category
            if annotation.category:
                result["properties"]["category"] = annotation.category

            # Add fix suggestion
            if include_suggestions and annotation.suggestion:
                result["fixes"] = [
                    {
                        "description": {
                            "text": annotation.suggestion,
                        }
                    }
                ]

            results.append(result)

        return results
