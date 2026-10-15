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


def test_publish_workflow_supplies_build_number_to_every_project_image():
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
    dtvp_version = _project_version(ROOT / "pyproject.toml")
    root_lock = ROOT / "uv.lock"
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(encoding="utf-8")
    assert _locked_package_version(root_lock, "dtvp") == dtvp_version
    assert "Release tag v$RELEASE_VERSION does not match packaged version" in workflow
    assert "TAG_DTVP_VERSION=$(git show" in workflow


def test_dtvp_packaging_and_deployment_exclude_bundled_agentyzer():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(encoding="utf-8")
    compose = (ROOT / "compose.yml").read_text(encoding="utf-8")
    metadata = _project_metadata(ROOT / "pyproject.toml")
    with (ROOT / "uv.lock").open("rb") as handle:
        names = {package["name"] for package in tomllib.load(handle)["package"]}
    assert not names.intersection({"agentyzer", "langgraph", "ormsgpack"})
    assert metadata["tool"]["pytest"]["ini_options"]["testpaths"] == ["tests"]
    assert "agentyzer" not in workflow.lower()
    assert "agentyzer" not in compose.lower()
    assert "DTVP_CODE_ANALYSIS_URL: ${DTVP_CODE_ANALYSIS_URL:-}" in compose
    assert "/dtvp:{2}" in workflow
    assert "/dtvp:latest" in workflow
