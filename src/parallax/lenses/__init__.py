"""Lenses module for Parallax."""

from parallax.lenses.base import AnalysisContext, Lens, LensRegistry
from parallax.lenses.security import SecurityLens

__all__ = ["Lens", "LensRegistry", "AnalysisContext", "SecurityLens"]
