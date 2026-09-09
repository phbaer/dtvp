import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _project_metadata(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _project_version(path: Path) -> str:
    return str(_project_metadata(path)["project"]["version"])


def _locked_package_version(path: Path, package_name: str) -> str:
    with path.open("rb") as handle:
        packages = tomllib.load(handle)["package"]
    package = next(
        package for package in packages if package["name"] == package_name
    )
    return str(package["version"])


def _locked_package(path: Path, package_name: str) -> dict:
    with path.open("rb") as handle:
        packages = tomllib.load(handle)["package"]
    return next(package for package in packages if package["name"] == package_name)


def test_dtvp_container_prints_packaged_project_version_before_server_start():
    start_script = (ROOT / "start.sh").read_text(encoding="utf-8")
    dockerfiles = [
        (ROOT / "Dockerfile").read_text(encoding="utf-8"),
        (ROOT / "Dockerfile.free-threaded").read_text(encoding="utf-8"),
    ]

    version_lookup = 'open("/app/pyproject.toml", "rb")'
    version_output = "printf 'DTVP version: %s (build number: %s)\\n'"
    server_start = "exec /app/.venv/bin/uvicorn"

    assert all("ARG BUILD_NUMBER=unknown" in dockerfile for dockerfile in dockerfiles)
    assert all(
        "DTVP_BUILD_NUMBER=$BUILD_NUMBER" in dockerfile for dockerfile in dockerfiles
    )
    assert version_lookup in start_script
    assert "DTVP_VERSION=${DTVP_VERSION:-unknown}" in start_script
    assert "DTVP_BUILD_NUMBER=${DTVP_BUILD_NUMBER:-unknown}" in start_script
    assert version_output in start_script
    assert start_script.index(version_output) < start_script.index(server_start)


def test_agentyzer_container_prints_packaged_project_version_before_server_start():
    dockerfile = (ROOT / "agentyzer" / "Dockerfile").read_text(encoding="utf-8")
    start_script = (ROOT / "agentyzer" / "start.sh").read_text(encoding="utf-8")

    version_lookup = 'version("agentyzer")'
    version_output = "printf 'Agentyzer version: %s (build number: %s)\\n'"
    server_start = "exec uv run --no-sync uvicorn"

    assert "COPY start.sh ./start.sh" in dockerfile
    assert "RUN chmod +x ./start.sh" in dockerfile
    assert 'CMD ["/app/start.sh"]' in dockerfile
    assert "ARG BUILD_NUMBER=unknown" in dockerfile
    assert "ARG AGENTYZER_BUILD_VERSION" in dockerfile
    assert "COPY src/__init__.py src/build_version.py ./src/" in dockerfile
    assert "AGENTYZER_BUILD_NUMBER=$BUILD_NUMBER" in dockerfile
    assert version_lookup in start_script
    assert "AGENTYZER_VERSION=${AGENTYZER_VERSION:-unknown}" in start_script
    assert "AGENTYZER_BUILD_NUMBER=${AGENTYZER_BUILD_NUMBER:-unknown}" in start_script
    assert version_output in start_script
    assert start_script.index(version_output) < start_script.index(server_start)


def test_publish_workflow_supplies_build_number_to_every_project_image():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("BUILD_NUMBER=${{ github.run_number }}") == 2


def test_uv_release_is_discovered_without_a_hard_coded_tool_version():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )
    dockerfile = (ROOT / "Dockerfile.free-threaded").read_text(encoding="utf-8")

    assert "UV_VERSION" not in workflow
    assert workflow.count("uses: astral-sh/setup-uv@") == 4
    assert "ARG UV_IMAGE=ghcr.io/astral-sh/uv:alpine" in dockerfile
    assert "FROM ${UV_IMAGE}" in dockerfile
    assert "UV_VERSION" not in dockerfile


def test_release_versions_are_lockstep_and_validated_before_tagging():
    dtvp_version = _project_version(ROOT / "pyproject.toml")
    agentyzer_metadata = _project_metadata(ROOT / "agentyzer" / "pyproject.toml")
    root_lock = ROOT / "uv.lock"
    agentyzer_lock = ROOT / "agentyzer" / "uv.lock"
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "version" not in agentyzer_metadata["project"]
    assert agentyzer_metadata["project"]["dynamic"] == ["version"]
    assert agentyzer_metadata["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "src.build_version.__version__"
    }
    assert _locked_package_version(root_lock, "dtvp") == dtvp_version
    assert "version" not in _locked_package(root_lock, "agentyzer")
    assert "version" not in _locked_package(agentyzer_lock, "agentyzer")
    assert "AGENTYZER_VERSION=$(cd agentyzer" not in workflow
    assert (
        "AGENTYZER_BUILD_VERSION=${{ steps.get_version.outputs.PACKAGE_VERSION }}"
        in workflow
    )
    assert "Release tag v$RELEASE_VERSION does not match packaged version" in workflow
    assert "TAG_DTVP_VERSION=$(git show" in workflow
    assert "TAG_AGENTYZER_VERSION=$(git show" not in workflow


def test_release_workflow_publishes_dtvp_and_agentyzer_version_tags():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "/dtvp:{2}" in workflow
    assert "/agentyzer:{2}" in workflow
    assert "/dtvp:latest" in workflow
    assert "/agentyzer:latest" in workflow
