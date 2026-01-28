"""Output formatters for Parallax."""

from parallax.output.base import Formatter
from parallax.output.json import JSONFormatter
from parallax.output.markdown import MarkdownFormatter
from parallax.output.sarif import SARIFFormatter
from parallax.output.text import TextFormatter

_FORMATTERS: dict[str, type[Formatter]] = {
    "text": TextFormatter,
    "json": JSONFormatter,
    "sarif": SARIFFormatter,
    "markdown": MarkdownFormatter,
}


def get_formatter(name: str) -> Formatter:
    """Get a formatter by name.

    Args:
        name: Formatter name (text, json, sarif, markdown).

    Returns:
        Formatter instance.

    Raises:
        ValueError: If formatter name is unknown.
    """
    if name not in _FORMATTERS:
        raise ValueError(f"Unknown formatter: {name}")
    return _FORMATTERS[name]()


__all__ = [
    "Formatter",
    "TextFormatter",
    "JSONFormatter",
    "SARIFFormatter",
    "MarkdownFormatter",
    "get_formatter",
]
