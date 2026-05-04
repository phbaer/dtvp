import os
import tomllib
from pathlib import Path
from importlib.metadata import version, PackageNotFoundError


def get_app_version():
    # 1. Try installed package metadata
    try:
        return version("dtvp")
    except PackageNotFoundError:
        pass

    # 2. Try pyproject.toml (dev mode)
    try:
        pyproject_path = Path(__file__).parent / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        return data["project"]["version"]
    except Exception:
        pass

    return "0.0.0"


VERSION = get_app_version()
BUILD_COMMIT = os.getenv("DTVP_BUILD_COMMIT", "unknown")
