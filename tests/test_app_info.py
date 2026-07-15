from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dtvp.app_info_routes import AppInfoRouteDeps, create_app_info_router
from dtvp.app_info_services import (
    build_sbom_html,
    get_sbom_path,
    load_changelog_content,
    load_pyproject_metadata,
)


def test_load_pyproject_metadata_reads_supported_project_fields(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "example"
version = "2.3.4"
authors = [{name = "Example Author"}]
urls = {Homepage = "https://example.com"}
""".strip(),
        encoding="utf-8",
    )

    assert load_pyproject_metadata(str(tmp_path)) == {
        "name": "example",
        "version": "2.3.4",
        "authors": [{"name": "Example Author"}],
        "urls": {"Homepage": "https://example.com"},
    }


def test_load_pyproject_metadata_returns_empty_when_file_is_missing(tmp_path):
    assert load_pyproject_metadata(str(tmp_path)) == {}


def test_changelog_and_sbom_helpers_handle_present_and_missing_files(tmp_path):
    assert load_changelog_content(str(tmp_path)) == "Changelog not available."
    assert get_sbom_path("backend.json", str(tmp_path)) is None

    (tmp_path / "CHANGELOG.md").write_text("# Changes\n", encoding="utf-8")
    sbom_dir = tmp_path / "sbom"
    sbom_dir.mkdir()
    sbom_file = sbom_dir / "backend.json"
    sbom_file.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")

    assert load_changelog_content(str(tmp_path)) == "# Changes\n"
    assert get_sbom_path("backend.json", str(tmp_path)) == str(sbom_file)


def test_build_sbom_html_embeds_content_and_download_link():
    html = build_sbom_html('{"bomFormat":"CycloneDX"}')

    assert "DTVP CycloneDX SBOM" in html
    assert "href='/api/sbom'" in html
    assert '<pre>{"bomFormat":"CycloneDX"}</pre>' in html


@pytest.fixture
def app_info_client(tmp_path):
    backend = tmp_path / "backend.json"
    frontend = tmp_path / "frontend.json"
    html = tmp_path / "html.json"
    backend.write_text('{"component":"backend"}', encoding="utf-8")
    frontend.write_text('{"component":"frontend"}', encoding="utf-8")
    html.write_text('{"component":"html"}', encoding="utf-8")
    paths: dict[str, Path] = {
        "backend.json": backend,
        "frontend.json": frontend,
        "html.json": html,
    }

    deps = AppInfoRouteDeps(
        version="2.3.4",
        build_commit="abc123",
        load_pyproject_metadata=lambda: {"name": "dtvp"},
        get_cache_status=lambda: {"ready": True},
        load_changelog_content=lambda: "changes",
        get_sbom_path=lambda filename: str(paths[filename]) if filename in paths else None,
        read_text=lambda path: Path(path).read_text(encoding="utf-8"),
        build_sbom_html=build_sbom_html,
        backend_sbom_filename="backend.json",
        frontend_sbom_filename="frontend.json",
        html_sbom_filename="html.json",
        media_type_json="application/json",
    )
    app = FastAPI(title="DTVP test", version="2.3.4", description="test API")
    app.include_router(
        create_app_info_router(app, deps, not_found_response={}),
        prefix="/api",
    )
    return TestClient(app), deps, paths


def test_app_info_routes_return_metadata_and_generated_openapi(app_info_client):
    client, _deps, _paths = app_info_client

    assert client.get("/api/version").json() == {
        "version": "2.3.4",
        "build": "abc123",
    }
    assert client.get("/api/metadata").json() == {"name": "dtvp"}
    assert client.get("/api/cache-status").json() == {"ready": True}
    assert client.get("/api/changelog").json() == {"content": "changes"}

    openapi = client.get("/api/openapi.json").json()
    assert openapi["info"]["title"] == "DTVP test"
    assert "/api/version" in openapi["paths"]


@pytest.mark.parametrize(
    ("endpoint", "expected_content"),
    [
        ("/api/sbom", b'{"component":"backend"}'),
        ("/api/sbom/backend", b'{"component":"backend"}'),
        ("/api/sbom/frontend", b'{"component":"frontend"}'),
    ],
)
def test_app_info_sbom_download_routes(
    app_info_client,
    endpoint,
    expected_content,
):
    client, _deps, _paths = app_info_client

    response = client.get(endpoint)

    assert response.status_code == 200
    assert response.content == expected_content
    assert response.headers["content-type"] == "application/json"


def test_app_info_html_sbom_route_renders_file(app_info_client):
    client, _deps, _paths = app_info_client

    response = client.get("/api/sbom/html")

    assert response.status_code == 200
    assert "DTVP CycloneDX SBOM" in response.text
    assert '{"component":"html"}' in response.text


@pytest.mark.parametrize(
    ("endpoint", "detail"),
    [
        (
            "/api/sbom",
            "Backend SBOM not available. Generate in CI and include in container at /sbom/dtvp-backend-cyclonedx.json.",
        ),
        (
            "/api/sbom/backend",
            "Backend SBOM not available. Generate in CI and include in container at /sbom/dtvp-backend-cyclonedx.json.",
        ),
        (
            "/api/sbom/frontend",
            "Frontend SBOM not available. Generate in CI and include in container at /sbom/dtvp-frontend-cyclonedx.json.",
        ),
        (
            "/api/sbom/html",
            "SBOM not available. Generate in CI and include in container at /sbom/html.json.",
        ),
    ],
)
def test_app_info_sbom_routes_report_missing_artifacts(
    app_info_client,
    endpoint,
    detail,
):
    client, deps, _paths = app_info_client
    object.__setattr__(deps, "get_sbom_path", lambda _filename: None)

    response = client.get(endpoint)

    assert response.status_code == 404
    assert response.json() == {"detail": detail}


def test_app_info_metadata_route_reports_missing_pyproject(app_info_client):
    client, deps, _paths = app_info_client
    object.__setattr__(deps, "load_pyproject_metadata", lambda: {})

    response = client.get("/api/metadata")

    assert response.status_code == 404
    assert response.json() == {"detail": "pyproject.toml metadata not found"}
