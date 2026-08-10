import tomllib
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from unittest.mock import patch

from src import version


def test_get_app_version_reads_agentyzer_pyproject_without_package_metadata():
    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject_path.open("rb") as handle:
        expected_version = tomllib.load(handle)["project"]["version"]

    with (
        patch.object(version, "version", side_effect=PackageNotFoundError),
        patch.object(version, "_find_pyproject_path", return_value=pyproject_path),
    ):
        assert version.get_app_version() == expected_version


def test_get_app_version_falls_back_when_metadata_and_pyproject_are_missing():
    with (
        patch.object(version, "version", side_effect=PackageNotFoundError),
        patch.object(version, "_find_pyproject_path", return_value=None),
    ):
        assert version.get_app_version() == "0.0.0"
