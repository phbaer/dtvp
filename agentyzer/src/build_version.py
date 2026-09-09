"""Resolve Agentyzer's package version from the monorepo release metadata."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path


def get_build_version() -> str:
    """Return the release version supplied by the build or the repository root."""
    build_version = os.getenv("AGENTYZER_BUILD_VERSION", "").strip()
    if build_version:
        return build_version

    root_pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    with root_pyproject.open("rb") as handle:
        version = str(tomllib.load(handle)["project"]["version"]).strip()
    if not version:
        raise ValueError(f"Project version is empty in {root_pyproject}")
    return version


__version__ = get_build_version()
