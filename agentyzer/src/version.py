"""Agentyzer package and build identity."""

from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _find_pyproject_path() -> Path | None:
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "pyproject.toml"
        if candidate.exists():
            return candidate
    return None


def get_app_version() -> str:
    """Return installed metadata, with a source-checkout fallback."""
    try:
        return version("agentyzer")
    except PackageNotFoundError:
        pass

    try:
        pyproject_path = _find_pyproject_path()
        if pyproject_path is None:
            raise FileNotFoundError("pyproject.toml not found")
        with pyproject_path.open("rb") as handle:
            return str(tomllib.load(handle)["project"]["version"])
    except Exception:
        return "0.0.0"


VERSION = get_app_version()
