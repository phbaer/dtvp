import tomllib
from pathlib import Path
from unittest.mock import patch


def test_get_app_version_reads_repo_pyproject_when_package_metadata_missing():
    from importlib.metadata import PackageNotFoundError

    import dtvp.version as version

    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject_path.open("rb") as handle:
        expected_version = tomllib.load(handle)["project"]["version"]

    with (
        patch.object(version, "version", side_effect=PackageNotFoundError),
        patch.object(version, "_find_pyproject_path", return_value=pyproject_path),
    ):
        assert version.get_app_version() == expected_version


def test_get_app_version_fallback():
    # importlib.metadata.version raises PackageNotFoundError if not found.
    # But checking source code in version.py:
    # try: return version("dtvp") except PackageNotFoundError: pass
    from importlib.metadata import PackageNotFoundError

    with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
        with patch("builtins.open", side_effect=FileNotFoundError):
            from importlib import reload

            import dtvp.version as version

            reload(version)
            assert version.get_app_version() == "0.0.0"

    # Restore
    from importlib import reload

    import dtvp.version as version

    reload(version)
