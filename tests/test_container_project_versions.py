import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _project_metadata(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


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


def test_publish_workflow_supplies_build_number_to_the_dtvp_image():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("BUILD_NUMBER=${{ github.run_number }}") == 1


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


def test_dtvp_release_version_is_validated_before_tagging():
    metadata = _project_metadata(ROOT / "pyproject.toml")
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert _locked_package(ROOT / "uv.lock", "dtvp")["version"] == metadata["project"][
        "version"
    ]
    assert "Release tag v$RELEASE_VERSION does not match packaged version" in workflow
    assert "TAG_DTVP_VERSION=$(git show" in workflow
    assert "agentyzer" not in workflow.lower()


def test_release_workflow_publishes_only_dtvp_version_tags():
    workflow = (ROOT / ".github/workflows/build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "/dtvp:{2}" in workflow
    assert "/dtvp:latest" in workflow
    assert "agentyzer" not in workflow.lower()
