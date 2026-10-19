"""The scale playground uses real HTTP workflows and never resets existing work."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from dtvp.config import Settings
from dtvp.main import create_app
from scripts.knowledge_scale_demo import ROOTS, VERSIONS, document, seed


@pytest.fixture
def app(tmp_path):
    return create_app(
        Settings(
            _env_file=None,
            playground=True,
            database_url="sqlite:///:memory:",
            artifact_dir=tmp_path / "artifacts",
            frontend_dir=tmp_path / "absent",
        )
    )


def test_real_native_imports_two_team_contexts_diff_raw_bytes_and_repeat_preserves_edits(app):
    with TestClient(app) as client:
        result = seed(client, products=1, packages=12, vulnerabilities=6)
        assert result["totals"]["created_products"] == 1
        project = result["created"][0]
        base = f"/api/v1/projects/{project['project_id']}"
        workspaces = []
        for version in VERSIONS:
            response = client.get(f"{base}/versions/{version}/workspace", params={"limit": 200})
            assert response.status_code == 200, response.text
            value = response.json()
            workspaces.append(value)
            assert {row["context"]["root_ref"] for row in value["items"]} == set(ROOTS)
            assert len({row["context"]["team_id"] for row in value["items"]}) == 2
            assert all(
                row["coverage"]["status"] == "unassessed" and row["published_score"] is None
                for row in value["items"]
            )
            raw = client.get(f"{base}/states/{value['state']}/source").content
            assert (
                raw
                == (
                    json.dumps(document(12, 6, version), ensure_ascii=False, indent=2) + "\n"
                ).encode()
            )
            baseline = app.state.knowledge.load(
                app.state.knowledge.records(value["state"], "inventory")["baseline"]
            )
            assert (
                baseline["collection"]["package_coverage"]
                == baseline["collection"]["license_coverage"]
                == "unknown"
            )
        current = workspaces[-1]
        shared = [row for row in current["items"] if row["vulnerability_id"] == "CVE-2099-10000"]
        assert len(shared) == 2 and len({row["context_id"] for row in shared}) == 2
        assert len({row["context"]["team_id"] for row in shared}) == 1
        diff = client.get(
            f"{base}/compare", params={"before": workspaces[0]["state"], "after": current["state"]}
        )
        assert diff.status_code == 200, diff.text
        assert diff.json()["changes"]["inventory"]["added"]
        assert diff.json()["changes"]["inventory"]["removed"]
        assert workspaces[0]["statistics"]["totals"]["unique_vulnerabilities"] == 6
        assert current["statistics"]["totals"]["unique_vulnerabilities"] == 6
        assert "CVE-2099-10005" not in {row["vulnerability_id"] for row in current["items"]}
        assert "CVE-2099-20005" in {row["vulnerability_id"] for row in current["items"]}
        # An interactive owner annotation must survive every subsequent seed run.
        row = current["items"][0]
        response = client.put(
            f"{base}/versions/{VERSIONS[1]}/metadata",
            json={
                "request_id": "interactive",
                "expected": current["state"],
                "expected_revision": None,
                "component_ref": row["context"]["component_ref"],
                "annotations": {"notes": "Keep interactive work"},
                "provenance": {"source": "Playground operator"},
                "rationale": "Interactive annotation",
            },
        )
        assert response.status_code == 201, response.text
        head = app.state.knowledge.head()
        references = app.state.knowledge.references()
        again = seed(client, products=1, packages=18, vulnerabilities=9)
        assert again["totals"]["created_products"] == 0 and again["totals"]["skipped_products"] == 1
        assert app.state.knowledge.head() == head and app.state.knowledge.references() == references
        assert (
            client.get(f"{base}/versions/{VERSIONS[1]}/workspace").json()["state"]
            == response.json()["updates"][0]["target"]
        )


def test_non_playground_confirmation_blocks_all_resource_writes():
    requests = []

    def handle(request):
        requests.append((request.method, request.url.path))
        if request.url.path.endswith("/playground/login"):
            return httpx.Response(
                200, json={}, headers={"set-cookie": "dtvp_csrf=synthetic; Path=/"}
            )
        if request.url.path == "/api/v1/me":
            return httpx.Response(200, json={"playground": False})
        raise AssertionError("No resources may be read or written before playground confirmation")

    with httpx.Client(
        base_url="http://testserver", transport=httpx.MockTransport(handle)
    ) as client:
        with pytest.raises(RuntimeError, match="verified playground"):
            seed(client, products=1, packages=6, vulnerabilities=1)
    assert requests == [("POST", "/api/v1/playground/login"), ("GET", "/api/v1/me")]


def test_production_has_no_playground_login_and_cannot_seed(tmp_path):
    app = create_app(
        Settings(
            _env_file=None,
            playground=False,
            session_secret="production-test-secret-00000000000000",
            database_url="postgresql+psycopg://unused:unused@127.0.0.1/unused",
            artifact_dir=tmp_path / "production",
            frontend_dir=tmp_path / "absent",
        )
    )
    # No production database/lifespan is started just to inspect route admission.
    client = TestClient(app)
    before = app.state.knowledge.head()
    try:
        with pytest.raises(httpx.HTTPStatusError):
            seed(client, products=1, packages=6, vulnerabilities=1)
        assert app.state.knowledge.head() == before
    finally:
        client.close()


@pytest.mark.parametrize(
    "options",
    [
        {"products": 21},
        {"packages": 2001},
        {"packages": 5},
        {"vulnerabilities": 251},
        {"products": True},
    ],
)
def test_scale_options_are_bounded_before_login(options):
    with pytest.raises(ValueError, match="must be an integer"):
        seed(None, **options)
