"""Tests for package initialization."""


def test_version_accessible():
    """Verify version is accessible from package."""
    from parallax import __version__

    assert __version__ == "0.1.0"


def test_package_imports():
    """Verify package imports without error."""
    import parallax
    import parallax.cli
    import parallax.core
    import parallax.diff
    import parallax.lang
    import parallax.lenses
    import parallax.output

    # If we get here, imports succeeded
    assert parallax is not None
