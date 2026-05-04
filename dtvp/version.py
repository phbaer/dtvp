import os
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


def get_app_version():
    # 1. Try installed package metadata
    try:
        return version("dtvp")
    except PackageNotFoundError:
        pass

    # 2. Try pyproject.toml (dev mode)
    try:
        pyproject_path = _find_pyproject_path()
        if pyproject_path is None:
            raise FileNotFoundError("pyproject.toml not found")
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        return data["project"]["version"]
    except Exception:
        pass

    return "0.0.0"


VERSION = get_app_version()
BUILD_COMMIT = os.getenv("DTVP_BUILD_COMMIT", "unknown")
