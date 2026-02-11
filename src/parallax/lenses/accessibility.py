"""Accessibility lens for Parallax.

Detects common accessibility issues in HTML and JSX code.
"""

import re

from parallax.core.types import Annotation, Location, Severity
from parallax.lenses.base import AnalysisContext, Lens, LensRegistry


# Patterns for detecting accessibility issues
IMG_TAG_PATTERN = re.compile(r"<img\s+[^>]*>", re.IGNORECASE)
ALT_ATTR_PATTERN = re.compile(r'\balt\s*=\s*["\'][^"\']+["\']', re.IGNORECASE)
EMPTY_ALT_PATTERN = re.compile(r'\balt\s*=\s*["\']["\']', re.IGNORECASE)

# Interactive elements that often need ARIA labels
BUTTON_NO_TEXT_PATTERN = re.compile(
    r"<button[^>]*>\s*<(?:img|svg|i|span)[^>]*>\s*</button>", re.IGNORECASE | re.DOTALL
)
ICON_BUTTON_PATTERN = re.compile(
    r"<button[^>]*class\s*=\s*[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.IGNORECASE
)
ARIA_LABEL_PATTERN = re.compile(
    r'\baria-label\s*=\s*["\'][^"\']+["\']', re.IGNORECASE
)
ARIA_LABELLEDBY_PATTERN = re.compile(
    r'\baria-labelledby\s*=\s*["\'][^"\']+["\']', re.IGNORECASE
)

# Link patterns
LINK_PATTERN = re.compile(r"<a\s+[^>]*>.*?</a>", re.IGNORECASE | re.DOTALL)
EMPTY_LINK_PATTERN = re.compile(r"<a\s+[^>]*>\s*</a>", re.IGNORECASE | re.DOTALL)

# Form input patterns
INPUT_PATTERN = re.compile(r"<input\s+[^>]*>", re.IGNORECASE)
LABEL_FOR_PATTERN = re.compile(r'\bfor\s*=\s*["\'][^"\']+["\']', re.IGNORECASE)
ID_PATTERN = re.compile(r'\bid\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

# JSX patterns (self-closing and expressions)
JSX_IMG_PATTERN = re.compile(r"<img\s+[^/]*/>", re.IGNORECASE)


@LensRegistry.register
class AccessibilityLens(Lens):
    """Accessibility issue detection lens."""

    @property
    def name(self) -> str:
        return "accessibility"

    @property
    def description(self) -> str:
        return "Detects common accessibility issues like missing alt text, ARIA labels, and form labels"

    def analyze(self, context: AnalysisContext) -> list[Annotation]:
        """Analyze code for accessibility issues."""
        annotations: list[Annotation] = []

        for path, ast in context.files.items():
            # Analyze HTML, JSX, and TSX files
            if not path.endswith((".html", ".htm", ".jsx", ".tsx", ".vue")):
                continue

            source = ast.source.decode("utf-8")
            lines = source.split("\n")

            annotations.extend(self._check_img_alt(path, lines, context))
            annotations.extend(self._check_button_labels(path, lines, context))
            annotations.extend(self._check_empty_links(path, lines, context))
            annotations.extend(self._check_form_labels(path, source, lines, context))

        return annotations

    def _check_img_alt(
        self, path: str, lines: list[str], context: AnalysisContext
    ) -> list[Annotation]:
        """Check for images missing alt attributes."""
        annotations = []

        for line_num, line in enumerate(lines, start=1):
            if not context.is_line_changed(path, line_num):
                continue

            # Find all img tags on this line
            for match in IMG_TAG_PATTERN.finditer(line):
                img_tag = match.group(0)

                # Check for empty alt first (alt="" or alt='')
                if EMPTY_ALT_PATTERN.search(img_tag):
                    # Empty alt is valid for decorative images, but flag as info
                    # Check if it's likely decorative (has role="presentation" or aria-hidden)
                    if 'role="presentation"' not in img_tag.lower() and 'aria-hidden="true"' not in img_tag.lower():
                        annotations.append(
                            Annotation(
                                lens="accessibility",
                                rule="empty_alt_text",
                                location=Location(
                                    file=path,
                                    start_line=line_num,
                                    end_line=line_num,
                                ),
                                severity=Severity.INFO,
                                confidence=0.7,
                                message='Image has empty alt text - ensure this is intentional for decorative images',
                                suggestion='If decorative, consider adding role="presentation" or aria-hidden="true"',
                            )
                        )
                # Check if alt attribute is present (non-empty)
                elif not ALT_ATTR_PATTERN.search(img_tag):
                    # Also check for any alt= (including empty)
                    if 'alt=' not in img_tag.lower():
                        annotations.append(
                            Annotation(
                                lens="accessibility",
                                rule="missing_alt_text",
                                location=Location(
                                    file=path,
                                    start_line=line_num,
                                    end_line=line_num,
                                ),
                                severity=Severity.HIGH,
                                confidence=0.95,
                                message="Image is missing alt text - screen readers cannot describe this image",
                                suggestion='Add an alt attribute: <img src="..." alt="Description of image">',
                            )
                        )

            # Also check JSX self-closing img tags
            for match in JSX_IMG_PATTERN.finditer(line):
                img_tag = match.group(0)
                if not ALT_ATTR_PATTERN.search(img_tag):
                    # Don't double-report if already caught by IMG_TAG_PATTERN
                    if IMG_TAG_PATTERN.search(img_tag):
                        continue
                    annotations.append(
                        Annotation(
                            lens="accessibility",
                            rule="missing_alt_text",
                            location=Location(
                                file=path,
                                start_line=line_num,
                                end_line=line_num,
                            ),
                            severity=Severity.HIGH,
                            confidence=0.95,
                            message="Image is missing alt text - screen readers cannot describe this image",
                            suggestion='Add an alt attribute: <img src="..." alt="Description of image" />',
                        )
                    )

        return annotations

    def _check_button_labels(
        self, path: str, lines: list[str], context: AnalysisContext
    ) -> list[Annotation]:
        """Check for buttons that may need ARIA labels."""
        annotations = []

        for line_num, line in enumerate(lines, start=1):
            if not context.is_line_changed(path, line_num):
                continue

            # Check for icon-only buttons (buttons with only icon/svg/img inside)
            if ICON_BUTTON_PATTERN.search(line) or "button" in line.lower():
                # Look for buttons that might be icon-only
                if "<button" in line.lower():
                    # Check if this button has aria-label or aria-labelledby
                    if not ARIA_LABEL_PATTERN.search(line) and not ARIA_LABELLEDBY_PATTERN.search(line):
                        # Check if it looks like an icon button (has icon class or contains svg/img)
                        if ("icon" in line.lower() or "<svg" in line.lower() or
                            "<img" in line.lower() or "<i " in line.lower()):
                            annotations.append(
                                Annotation(
                                    lens="accessibility",
                                    rule="missing_button_label",
                                    location=Location(
                                        file=path,
                                        start_line=line_num,
                                        end_line=line_num,
                                    ),
                                    severity=Severity.MEDIUM,
                                    confidence=0.75,
                                    message="Icon button may be missing accessible label",
                                    suggestion='Add aria-label="Button purpose" to describe the button\'s action',
                                )
                            )

        return annotations

    def _check_empty_links(
        self, path: str, lines: list[str], context: AnalysisContext
    ) -> list[Annotation]:
        """Check for links without accessible text."""
        annotations = []

        for line_num, line in enumerate(lines, start=1):
            if not context.is_line_changed(path, line_num):
                continue

            # Check for links with only images/icons inside
            for match in LINK_PATTERN.finditer(line):
                link = match.group(0)
                # Get content between <a ...> and </a>
                content_match = re.search(r">(.+?)</a>", link, re.IGNORECASE | re.DOTALL)
                if content_match:
                    content = content_match.group(1).strip()
                    # If content is only whitespace, img tags, or icons
                    if not content or re.match(r"^\s*<(img|svg|i)[^>]*/?>\s*$", content, re.IGNORECASE):
                        if not ARIA_LABEL_PATTERN.search(link) and not ARIA_LABELLEDBY_PATTERN.search(link):
                            annotations.append(
                                Annotation(
                                    lens="accessibility",
                                    rule="empty_link",
                                    location=Location(
                                        file=path,
                                        start_line=line_num,
                                        end_line=line_num,
                                    ),
                                    severity=Severity.HIGH,
                                    confidence=0.85,
                                    message="Link has no accessible text - screen readers cannot describe where it goes",
                                    suggestion='Add text content or aria-label="Link description"',
                                )
                            )

        return annotations

    def _check_form_labels(
        self, path: str, source: str, lines: list[str], context: AnalysisContext
    ) -> list[Annotation]:
        """Check for form inputs without labels."""
        annotations = []

        # Collect all label 'for' attributes
        label_fors = set()
        for match in LABEL_FOR_PATTERN.finditer(source):
            for_val = re.search(r'["\']([^"\']+)["\']', match.group(0))
            if for_val:
                label_fors.add(for_val.group(1))

        for line_num, line in enumerate(lines, start=1):
            if not context.is_line_changed(path, line_num):
                continue

            for match in INPUT_PATTERN.finditer(line):
                input_tag = match.group(0)

                # Skip hidden inputs and submit/button types
                if 'type="hidden"' in input_tag.lower() or 'type="submit"' in input_tag.lower():
                    continue
                if 'type="button"' in input_tag.lower() or 'type="image"' in input_tag.lower():
                    continue

                # Check for id attribute
                id_match = ID_PATTERN.search(input_tag)

                # Check if input has aria-label or aria-labelledby
                has_aria_label = (
                    ARIA_LABEL_PATTERN.search(input_tag) or
                    ARIA_LABELLEDBY_PATTERN.search(input_tag)
                )

                # Check if there's a label with matching 'for'
                has_label = id_match and id_match.group(1) in label_fors

                if not has_aria_label and not has_label:
                    # Check for placeholder (not a proper label but better than nothing)
                    has_placeholder = 'placeholder=' in input_tag.lower()

                    if has_placeholder:
                        annotations.append(
                            Annotation(
                                lens="accessibility",
                                rule="placeholder_only_label",
                                location=Location(
                                    file=path,
                                    start_line=line_num,
                                    end_line=line_num,
                                ),
                                severity=Severity.LOW,
                                confidence=0.8,
                                message="Form input uses placeholder as only label - placeholders disappear when typing",
                                suggestion='Add a <label for="inputId"> or aria-label attribute',
                            )
                        )
                    else:
                        annotations.append(
                            Annotation(
                                lens="accessibility",
                                rule="missing_form_label",
                                location=Location(
                                    file=path,
                                    start_line=line_num,
                                    end_line=line_num,
                                ),
                                severity=Severity.MEDIUM,
                                confidence=0.85,
                                message="Form input has no associated label - screen readers cannot identify this field",
                                suggestion='Add a <label for="inputId"> or aria-label attribute',
                            )
                        )

        return annotations
