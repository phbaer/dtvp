from unittest.mock import patch


def test_get_app_version_fallback():
    # importlib.metadata.version raises PackageNotFoundError if not found.
    # But checking source code in version.py:
    # try: return version("dtvp") except PackageNotFoundError: pass
    from importlib.metadata import PackageNotFoundError

    with patch("importlib.metadata.version", side_effect=PackageNotFoundError):
        with patch("builtins.open", side_effect=FileNotFoundError):
            import version
            from importlib import reload

            reload(version)
            assert version.get_app_version() == "0.0.0"

    # Restore
    import version
    from importlib import reload

    reload(version)
