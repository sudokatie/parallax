"""Analysis engine for Parallax."""

import subprocess
from pathlib import Path

from parallax.core.config import Config
from parallax.core.suppression import (
    Suppression,
    SuppressionChecker,
    parse_file_suppressions,
)
from parallax.core.types import AnalysisResult, Annotation
from parallax.diff.parser import ParseError, parse_diff, parse_diff_file
from parallax.diff.types import ParsedDiff
from parallax.lang.base import FileAST
from parallax.lang.python import PythonAnalyzer
from parallax.lenses.base import AnalysisContext, Lens, LensRegistry


class EngineError(Exception):
    """Error during analysis."""

    pass


class AnalysisEngine:
    """Orchestrates diff analysis through lenses."""

    def __init__(
        self,
        config: Config,
        verbose: bool = False,
        quiet: bool = False,
    ) -> None:
        """Initialize the analysis engine.

        Args:
            config: Application configuration.
            verbose: Enable verbose output.
            quiet: Suppress progress output.
        """
        self.config = config
        self.verbose = verbose
        self.quiet = quiet
        self._python_analyzer = PythonAnalyzer()
        self._suppressions: dict[str, list[Suppression]] = {}

    def analyze(self, target: str) -> AnalysisResult:
        """Analyze a target (diff file or directory).

        Args:
            target: Path to diff file or directory with git changes.

        Returns:
            AnalysisResult with annotations and errors.

        Raises:
            EngineError: If analysis fails.
        """
        target_path = Path(target)

        # Parse the diff
        try:
            if target_path.is_dir():
                diff = self._get_git_diff(target_path)
            elif target_path.is_file():
                diff = parse_diff_file(str(target_path))
            else:
                raise EngineError(f"Target not found: {target}")
        except ParseError as e:
            raise EngineError(f"Failed to parse diff: {e}") from e
        except FileNotFoundError as e:
            raise EngineError(str(e)) from e

        if not diff.files:
            if not self.quiet:
                self._log("No changes to analyze")
            return AnalysisResult(target=target)

        if self.verbose:
            self._log(f"Found {len(diff.files)} changed file(s)")

        # Parse source files
        files = self._parse_source_files(diff, target_path)

        if self.verbose:
            self._log(f"Parsed {len(files)} source file(s)")

        # Run lenses
        annotations: list[Annotation] = []
        errors: list[str] = []

        for lens in self._get_enabled_lenses():
            if self.verbose:
                self._log(f"Running {lens.name} lens...")

            try:
                lens_config = self.config.get_lens_config(lens.name)
                context = AnalysisContext(
                    diff=diff,
                    files=files,
                    config=lens_config,
                )

                lens_annotations = lens.analyze(context)

                # Filter by severity threshold
                lens_annotations = [
                    a
                    for a in lens_annotations
                    if a.severity >= lens_config.severity_threshold
                ]

                # Filter by ignore patterns (config-based)
                lens_annotations = self._apply_ignore_rules(lens_annotations)

                # Filter by inline suppressions
                lens_annotations = self._apply_suppressions(lens_annotations)

                annotations.extend(lens_annotations)

                if self.verbose:
                    self._log(f"  Found {len(lens_annotations)} finding(s)")

            except Exception as e:
                error_msg = f"Lens '{lens.name}' failed: {e}"
                errors.append(error_msg)
                if self.verbose:
                    self._log(f"  Error: {e}")

        return AnalysisResult(
            target=target,
            annotations=annotations,
            errors=errors,
        )

    def _get_git_diff(self, directory: Path) -> ParsedDiff:
        """Get diff of uncommitted changes in a git directory.

        Args:
            directory: Path to git repository.

        Returns:
            ParsedDiff of uncommitted changes.

        Raises:
            EngineError: If git command fails.
        """
        try:
            # Get both staged and unstaged changes
            result = subprocess.run(
                ["git", "diff", "HEAD"],
                cwd=directory,
                capture_output=True,
                text=True,
                check=True,
            )
            diff_content = result.stdout

            # If no HEAD diff, try just staged changes
            if not diff_content.strip():
                result = subprocess.run(
                    ["git", "diff", "--cached"],
                    cwd=directory,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                diff_content = result.stdout

            # If still nothing, try unstaged changes
            if not diff_content.strip():
                result = subprocess.run(
                    ["git", "diff"],
                    cwd=directory,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                diff_content = result.stdout

            return parse_diff(diff_content)

        except subprocess.CalledProcessError as e:
            raise EngineError(f"Git command failed: {e.stderr}") from e
        except FileNotFoundError:
            raise EngineError("Git not found. Is git installed?")

    def _parse_source_files(
        self, diff: ParsedDiff, base_path: Path
    ) -> dict[str, FileAST]:
        """Parse source files referenced in the diff.

        Args:
            diff: Parsed diff.
            base_path: Base path for resolving file paths.

        Returns:
            Dict mapping file paths to FileAST objects.
        """
        files: dict[str, FileAST] = {}

        for file_diff in diff.files:
            if file_diff.is_binary:
                continue

            path = file_diff.new_path or file_diff.old_path
            if path is None:
                continue

            # Skip deleted files
            if file_diff.is_deleted:
                continue

            # Only parse Python files for now
            if not self._python_analyzer.supports_file(path):
                continue

            # Resolve full path
            if base_path.is_dir():
                full_path = base_path / path
            else:
                # For patch files, look relative to current directory
                full_path = Path(path)
                if not full_path.exists():
                    # Try relative to patch file location
                    full_path = base_path.parent / path

            if not full_path.exists():
                if self.verbose:
                    self._log(f"  Skipping {path} (file not found)")
                continue

            try:
                ast = self._python_analyzer.parse_file(str(full_path))
                files[path] = ast

                # Parse inline suppressions from source
                source = full_path.read_text()
                suppressions = parse_file_suppressions(source)
                if suppressions:
                    self._suppressions[path] = suppressions
                    if self.verbose:
                        self._log(f"  Found {len(suppressions)} suppression(s) in {path}")

            except Exception as e:
                if self.verbose:
                    self._log(f"  Failed to parse {path}: {e}")

        return files

    def _get_enabled_lenses(self) -> list[Lens]:
        """Get list of enabled lens instances.

        Returns:
            List of enabled Lens instances.
        """
        lenses: list[Lens] = []

        for lens_class in LensRegistry.all():
            lens = lens_class()
            if self.config.is_lens_enabled(lens.name):
                # Configure the lens
                lens_config = self.config.get_lens_config(lens.name)
                lens.configure(lens_config.rules)
                lenses.append(lens)

        return lenses

    def _apply_ignore_rules(
        self, annotations: list[Annotation]
    ) -> list[Annotation]:
        """Filter annotations based on ignore rules.

        Args:
            annotations: List of annotations.

        Returns:
            Filtered list of annotations.
        """
        if not self.config.ignore_paths and not self.config.ignore_rules:
            return annotations

        import fnmatch

        result = []
        for annotation in annotations:
            path = annotation.location.file
            rule_id = f"{annotation.lens}/{annotation.rule}"

            # Check path ignores
            ignored = False
            for pattern in self.config.ignore_paths:
                if fnmatch.fnmatch(path, pattern):
                    ignored = True
                    break

            if ignored:
                continue

            # Check rule-specific ignores
            if rule_id in self.config.ignore_rules:
                patterns = self.config.ignore_rules[rule_id]
                for pattern in patterns:
                    if pattern == "*" or fnmatch.fnmatch(path, pattern):
                        ignored = True
                        break

            if not ignored:
                result.append(annotation)

        return result

    def _apply_suppressions(
        self, annotations: list[Annotation]
    ) -> list[Annotation]:
        """Filter annotations based on inline suppression comments.

        Args:
            annotations: List of annotations.

        Returns:
            Filtered list of annotations.
        """
        if not self._suppressions:
            return annotations

        checker = SuppressionChecker(self._suppressions)
        result = []

        for annotation in annotations:
            rule_id = f"{annotation.lens}/{annotation.rule}"
            if not checker.is_suppressed(
                annotation.location.file,
                annotation.location.start_line,
                rule_id,
            ):
                result.append(annotation)
            elif self.verbose:
                self._log(f"  Suppressed: {rule_id} at {annotation.location.file}:{annotation.location.start_line}")

        return result

    def _log(self, message: str) -> None:
        """Log a message if not in quiet mode."""
        if not self.quiet:
            print(message)
