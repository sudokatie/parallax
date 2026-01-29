"""Parallax CLI entry point."""

import click

from parallax import __version__
from parallax.cli.commands import analyze, init, list_lenses


@click.group()
@click.version_option(version=__version__, prog_name="parallax")
def cli() -> None:
    """Parallax - Code review through multiple lenses.

    Analyze diffs through specialized lenses that each focus on different
    concerns: security, performance, maintainability, testing.
    """
    pass


# Register commands
cli.add_command(analyze)
cli.add_command(list_lenses, name="lenses")
cli.add_command(init)


def _import_lenses() -> None:
    """Import all lens modules to trigger registration."""
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
