"""Parallax CLI entry point."""

import sys
from pathlib import Path

import click

from parallax import __version__
from parallax.core.config import ConfigError, load_config, merge_cli_args
from parallax.core.engine import AnalysisEngine, EngineError
from parallax.core.types import Severity
from parallax.lenses.base import LensRegistry
from parallax.output import get_formatter


@click.group()
@click.version_option(version=__version__, prog_name="parallax")
def cli() -> None:
    """Parallax - Code review through multiple lenses.

    Analyze diffs through specialized lenses that each focus on different
    concerns: security, performance, maintainability, testing.
    """
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True), required=False, default=None)
@click.option(
    "--pr",
    "pr_url",
    type=str,
    default=None,
    help="GitHub/GitLab PR URL to analyze.",
)
@click.option(
    "--commit",
    "commit_sha",
    type=str,
    default=None,
    help="Specific commit SHA to analyze.",
)
@click.option(
    "--range",
    "commit_range",
    type=str,
    default=None,
    help="Commit range to analyze (base..head).",
)
@click.option(
    "-l",
    "--lens",
    "lenses",
    multiple=True,
    help="Run specific lens (repeatable).",
)
@click.option(
    "-L",
    "--exclude-lens",
    "exclude_lenses",
    multiple=True,
    help="Exclude specific lens (repeatable).",
)
@click.option(
    "-o",
    "--output",
    "output_format",
    type=click.Choice(["text", "json", "sarif", "markdown"]),
    default=None,
    help="Output format (default: text).",
)
@click.option(
    "-f",
    "--output-file",
    type=click.Path(),
    default=None,
    help="Write output to file (default: stdout).",
)
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Config file path (default: .parallax.yaml).",
)
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default=None,
    help="Minimum severity to report.",
)
@click.option(
    "--min-confidence",
    type=float,
    default=None,
    help="Minimum confidence 0.0-1.0 (default: 0.5).",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default=None,
    help="Exit non-zero if findings at this severity or above.",
)
@click.option(
    "--no-suggestions",
    is_flag=True,
    default=False,
    help="Omit fix suggestions from output.",
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose output.")
@click.option("-q", "--quiet", is_flag=True, help="Suppress progress output.")
def analyze(
    target: str | None,
    pr_url: str | None,
    commit_sha: str | None,
    commit_range: str | None,
    lenses: tuple[str, ...],
    exclude_lenses: tuple[str, ...],
    output_format: str | None,
    output_file: str | None,
    config_path: str | None,
    min_severity: str | None,
    min_confidence: float | None,
    fail_on: str | None,
    no_suggestions: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    """Analyze a diff/directory and output findings.

    TARGET can be a patch file (.patch, .diff) or a directory with
    uncommitted git changes. Alternatively, use --pr, --commit, or --range.
    """
    # Validate that exactly one target source is provided
    sources = [target, pr_url, commit_sha, commit_range]
    provided = [s for s in sources if s is not None]
    if len(provided) == 0:
        click.echo("Error: Must provide TARGET, --pr, --commit, or --range", err=True)
        sys.exit(2)
    if len(provided) > 1:
        click.echo("Error: Only one of TARGET, --pr, --commit, or --range can be specified", err=True)
        sys.exit(2)
    try:
        # Load configuration
        config = load_config(config_path)

        # Merge CLI arguments
        cli_args = {
            "min_confidence": min_confidence,
            "output_format": output_format,
            "fail_on": Severity(fail_on) if fail_on else None,
            "enable_lenses": list(lenses) if lenses else None,
            "disable_lenses": list(exclude_lenses) if exclude_lenses else None,
        }
        config = merge_cli_args(config, **cli_args)

        # Create engine and run analysis
        engine = AnalysisEngine(config, verbose=verbose, quiet=quiet)

        # Determine analysis mode
        if pr_url:
            result = engine.analyze_pr(pr_url)
        elif commit_sha:
            result = engine.analyze_commit(commit_sha)
        elif commit_range:
            result = engine.analyze_range(commit_range)
        else:
            result = engine.analyze(target)

        # Filter by min_severity if specified
        if min_severity:
            min_sev = Severity(min_severity)
            result.annotations = [
                a for a in result.annotations if a.severity >= min_sev
            ]

        # Filter by confidence
        result.annotations = [
            a for a in result.annotations if a.confidence >= config.min_confidence
        ]

        # Get formatter and output
        formatter = get_formatter(config.output_format)
        output = formatter.format(result, include_suggestions=not no_suggestions)

        if output_file:
            Path(output_file).write_text(output)
            if not quiet:
                click.echo(f"Output written to {output_file}")
        else:
            click.echo(output)

        # Exit with error code if findings at fail_on level
        if config.fail_on:
            failing = [a for a in result.annotations if a.severity >= config.fail_on]
            if failing:
                sys.exit(1)

    except ConfigError as e:
        click.echo(f"Configuration error: {e}", err=True)
        sys.exit(2)
    except EngineError as e:
        click.echo(f"Analysis error: {e}", err=True)
        sys.exit(3)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(3)


@cli.command("lenses")
def list_lenses() -> None:
    """List available lenses."""
    # Import lenses to trigger registration
    _import_lenses()

    click.echo("Available lenses:\n")
    for lens_class in LensRegistry.all():
        lens = lens_class()
        click.echo(f"  {lens.name}")
        click.echo(f"    {lens.description}\n")


@cli.command()
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing config file.",
)
def init(force: bool) -> None:
    """Create .parallax.yaml config file."""
    config_path = Path(".parallax.yaml")

    if config_path.exists() and not force:
        click.echo(
            "Config file already exists. Use --force to overwrite.", err=True
        )
        sys.exit(1)

    default_config = """\
# Parallax configuration
# https://github.com/katieblackabee/parallax

lenses:
  security:
    enabled: true
  maintainability:
    enabled: true
    rules:
      cyclomatic_complexity:
        threshold: 10
      function_length:
        max_lines: 50
  testing:
    enabled: true

settings:
  min_confidence: 0.5
  output_format: text
  # fail_on: high  # Uncomment to fail CI on high+ severity

ignore:
  paths:
    - "**/test_*.py"
    - "**/migrations/**"
  # rules:
  #   - security/hardcoded_secrets:tests/*
"""
    config_path.write_text(default_config)
    click.echo(f"Created {config_path}")


def _import_lenses() -> None:
    """Import all lens modules to trigger registration."""
    # Import lens modules - they auto-register via decorator
    from parallax.lenses import security  # noqa: F401

    try:
        from parallax.lenses import maintainability  # noqa: F401
    except ImportError:
        pass

    try:
        from parallax.lenses import testing  # noqa: F401
    except ImportError:
        pass


def main() -> None:
    """Main entry point."""
    _import_lenses()
    cli()


if __name__ == "__main__":
    main()
