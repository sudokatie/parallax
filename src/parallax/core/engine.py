"""Analysis engine for Parallax."""

import json
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

    def analyze_commit(self, commit_sha: str, repo_path: str = ".") -> AnalysisResult:
        """Analyze a specific commit.

        Args:
            commit_sha: Git commit SHA to analyze.
            repo_path: Path to git repository (default: current directory).

        Returns:
            AnalysisResult with annotations and errors.

        Raises:
            EngineError: If analysis fails.
        """
        repo = Path(repo_path)

        try:
            # Get diff for the specific commit
            result = subprocess.run(
                ["git", "show", "--format=", commit_sha],
                cwd=repo,
                capture_output=True,
                text=True,
                check=True,
            )
            diff_content = result.stdout

            if not diff_content.strip():
                if not self.quiet:
                    self._log(f"No changes in commit {commit_sha}")
                return AnalysisResult(target=f"commit:{commit_sha}")

            diff = parse_diff(diff_content)

        except subprocess.CalledProcessError as e:
            raise EngineError(f"Git command failed: {e.stderr}") from e
        except FileNotFoundError:
            raise EngineError("Git not found. Is git installed?")

        return self._analyze_diff(diff, repo, f"commit:{commit_sha}")

    def analyze_range(self, commit_range: str, repo_path: str = ".") -> AnalysisResult:
        """Analyze a range of commits.

        Args:
            commit_range: Git commit range (e.g., "base..head" or "base...head").
            repo_path: Path to git repository (default: current directory).

        Returns:
            AnalysisResult with annotations and errors.

        Raises:
            EngineError: If analysis fails.
        """
        repo = Path(repo_path)

        try:
            # Get diff for the commit range
            result = subprocess.run(
                ["git", "diff", commit_range],
                cwd=repo,
                capture_output=True,
                text=True,
                check=True,
            )
            diff_content = result.stdout

            if not diff_content.strip():
                if not self.quiet:
                    self._log(f"No changes in range {commit_range}")
                return AnalysisResult(target=f"range:{commit_range}")

            diff = parse_diff(diff_content)

        except subprocess.CalledProcessError as e:
            raise EngineError(f"Git command failed: {e.stderr}") from e
        except FileNotFoundError:
            raise EngineError("Git not found. Is git installed?")

        return self._analyze_diff(diff, repo, f"range:{commit_range}")

    def analyze_pr(self, pr_url: str) -> AnalysisResult:
        """Analyze a GitHub/GitLab pull request.

        Args:
            pr_url: URL of the PR to analyze.

        Returns:
            AnalysisResult with annotations and errors.

        Raises:
            EngineError: If analysis fails.
        """
        # Parse PR URL to extract info
        import re

        # GitHub pattern: https://github.com/owner/repo/pull/123
        github_pattern = r"github\.com/([^/]+)/([^/]+)/pull/(\d+)"
        # GitLab pattern: https://gitlab.com/owner/repo/-/merge_requests/123
        gitlab_pattern = r"gitlab\.com/([^/]+)/([^/]+)/-/merge_requests/(\d+)"

        github_match = re.search(github_pattern, pr_url)
        gitlab_match = re.search(gitlab_pattern, pr_url)

        if github_match:
            owner, repo, pr_num = github_match.groups()
            return self._analyze_github_pr(owner, repo, int(pr_num))
        elif gitlab_match:
            owner, repo, mr_num = gitlab_match.groups()
            return self._analyze_gitlab_mr(owner, repo, int(mr_num))
        else:
            raise EngineError(f"Unsupported PR URL format: {pr_url}")

    def _analyze_github_pr(self, owner: str, repo: str, pr_num: int) -> AnalysisResult:
        """Analyze a GitHub pull request.

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_num: Pull request number.

        Returns:
            AnalysisResult with annotations and errors.
        """
        try:
            import urllib.request
            import json

            # Fetch PR diff using GitHub API
            url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_num}"
            headers = {"Accept": "application/vnd.github.v3.diff"}

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                diff_content = response.read().decode("utf-8")

            if not diff_content.strip():
                if not self.quiet:
                    self._log(f"No changes in PR #{pr_num}")
                return AnalysisResult(target=f"github:{owner}/{repo}#{pr_num}")

            diff = parse_diff(diff_content)

            # For PRs, we need to clone or have the repo locally
            # For now, just analyze the diff without source file access
            if not self.quiet:
                self._log(f"Analyzing GitHub PR #{pr_num} (diff-only mode)")

            return self._analyze_diff_only(diff, f"github:{owner}/{repo}#{pr_num}")

        except urllib.error.HTTPError as e:
            raise EngineError(f"GitHub API error: {e.code} {e.reason}") from e
        except urllib.error.URLError as e:
            raise EngineError(f"Network error: {e.reason}") from e

    def _analyze_gitlab_mr(self, owner: str, repo: str, mr_num: int) -> AnalysisResult:
        """Analyze a GitLab merge request.

        Args:
            owner: Repository owner/namespace.
            repo: Repository name.
            mr_num: Merge request number.

        Returns:
            AnalysisResult with annotations and errors.
        """
        try:
            import urllib.request
            import urllib.parse

            # GitLab project ID is owner%2Frepo (URL encoded)
            project_id = urllib.parse.quote(f"{owner}/{repo}", safe="")
            url = f"https://gitlab.com/api/v4/projects/{project_id}/merge_requests/{mr_num}/changes"

            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8"))

            # GitLab returns changes differently, need to construct diff
            changes = data.get("changes", [])
            if not changes:
                if not self.quiet:
                    self._log(f"No changes in MR !{mr_num}")
                return AnalysisResult(target=f"gitlab:{owner}/{repo}!{mr_num}")

            # Construct unified diff from changes
            diff_lines = []
            for change in changes:
                diff_lines.append(f"diff --git a/{change['old_path']} b/{change['new_path']}")
                diff_lines.append(f"--- a/{change['old_path']}")
                diff_lines.append(f"+++ b/{change['new_path']}")
                diff_lines.append(change.get("diff", ""))

            diff_content = "\n".join(diff_lines)
            diff = parse_diff(diff_content)

            if not self.quiet:
                self._log(f"Analyzing GitLab MR !{mr_num} (diff-only mode)")

            return self._analyze_diff_only(diff, f"gitlab:{owner}/{repo}!{mr_num}")

        except urllib.error.HTTPError as e:
            raise EngineError(f"GitLab API error: {e.code} {e.reason}") from e
        except urllib.error.URLError as e:
            raise EngineError(f"Network error: {e.reason}") from e

    def _analyze_diff(
        self, diff: ParsedDiff, base_path: Path, target: str
    ) -> AnalysisResult:
        """Analyze a parsed diff with source file access.

        Args:
            diff: Parsed diff.
            base_path: Base path for resolving file paths.
            target: Target identifier for the result.

        Returns:
            AnalysisResult with annotations and errors.
        """
        if not diff.files:
            if not self.quiet:
                self._log("No changes to analyze")
            return AnalysisResult(target=target)

        if self.verbose:
            self._log(f"Found {len(diff.files)} changed file(s)")

        # Parse source files
        files = self._parse_source_files(diff, base_path)

        if self.verbose:
            self._log(f"Parsed {len(files)} source file(s)")

        return self._run_lenses(diff, files, target)

    def _analyze_diff_only(self, diff: ParsedDiff, target: str) -> AnalysisResult:
        """Analyze a diff without source file access (limited analysis).

        Args:
            diff: Parsed diff.
            target: Target identifier for the result.

        Returns:
            AnalysisResult with annotations and errors.
        """
        if not diff.files:
            if not self.quiet:
                self._log("No changes to analyze")
            return AnalysisResult(target=target)

        if self.verbose:
            self._log(f"Found {len(diff.files)} changed file(s)")
            self._log("Note: Running in diff-only mode (no source file access)")

        # Without source files, we can't do full AST analysis
        # Return result with a warning
        return AnalysisResult(
            target=target,
            annotations=[],
            errors=["Diff-only mode: Full AST analysis requires local repository access"],
        )

    def _run_lenses(
        self, diff: ParsedDiff, files: dict[str, FileAST], target: str
    ) -> AnalysisResult:
        """Run all enabled lenses on the diff.

        Args:
            diff: Parsed diff.
            files: Parsed source files.
            target: Target identifier for the result.

        Returns:
            AnalysisResult with annotations and errors.
        """
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
