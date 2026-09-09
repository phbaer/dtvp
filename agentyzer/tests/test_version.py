import tomllib
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from unittest.mock import patch

from src import build_version
from src import version


def test_get_app_version_uses_the_derived_build_version_without_package_metadata():
    with (
        patch.object(version, "version", side_effect=PackageNotFoundError),
        patch.object(build_version, "__version__", "release-version"),
    ):
        assert version.get_app_version() == "release-version"


def test_build_version_prefers_the_container_build_value(monkeypatch):
    monkeypatch.setenv("AGENTYZER_BUILD_VERSION", "release-version")

    assert build_version.get_build_version() == "release-version"


def test_build_version_reads_the_monorepo_release_version(monkeypatch):
    monkeypatch.delenv("AGENTYZER_BUILD_VERSION", raising=False)
    root_pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    with root_pyproject.open("rb") as handle:
        expected = tomllib.load(handle)["project"]["version"]

    assert build_version.get_build_version() == expected
