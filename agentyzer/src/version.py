"""Agentyzer package and build identity."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def get_app_version() -> str:
    """Return installed metadata, with a source-checkout fallback."""
    try:
        return version("agentyzer")
    except PackageNotFoundError:
        pass

    try:
        from src.build_version import __version__

        return __version__
    except (FileNotFoundError, KeyError, OSError, ValueError):
        return "0.0.0"


VERSION = get_app_version()
