import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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

    version_lookup = 'open("/app/pyproject.toml", "rb")'
    version_output = "printf 'Agentyzer version: %s (build number: %s)\\n'"
    server_start = "exec uv run --no-sync uvicorn"

    assert "COPY start.sh ./start.sh" in dockerfile
    assert "RUN chmod +x ./start.sh" in dockerfile
    assert 'CMD ["/app/start.sh"]' in dockerfile
    assert "ARG BUILD_NUMBER=unknown" in dockerfile
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

    assert workflow.count("BUILD_NUMBER=${{ github.run_number }}") == 3


def test_release_versions_are_lockstep_and_validated_before_tagging():
    with (ROOT / "pyproject.toml").open("rb") as handle:
        dtvp_version = tomllib.load(handle)["project"]["version"]
    with (ROOT / "agentyzer" / "pyproject.toml").open("rb") as handle:
        agentyzer_version = tomllib.load(handle)["project"]["version"]
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert dtvp_version == agentyzer_version
    assert workflow.count(
        "AGENTYZER_VERSION=$(cd agentyzer && uv version | awk '{print $2}')"
    ) == 2
    assert "does not match Agentyzer version" in workflow
    assert "Release tag v$RELEASE_VERSION does not match packaged version" in workflow
    assert "TAG_DTVP_VERSION=$(git show" in workflow
    assert "TAG_AGENTYZER_VERSION=$(git show" in workflow
    assert "does not contain matching DTVP and Agentyzer package versions" in workflow


def test_release_workflow_publishes_dtvp_and_agentyzer_version_tags():
    workflow = (ROOT / ".github" / "workflows" / "build-publish.yml").read_text(
        encoding="utf-8"
    )

    assert "/dtvp:{2}" in workflow
    assert "/agentyzer:{2}" in workflow
    assert "/dtvp:latest" in workflow
    assert "/agentyzer:latest" in workflow
