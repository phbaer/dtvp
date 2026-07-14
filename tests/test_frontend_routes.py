from fastapi import FastAPI
from fastapi.testclient import TestClient

from dtvp.frontend_routes import (
    FrontendRouteDeps,
    _inline_script_json,
    _render_index_html,
    register_frontend_routes,
)


def test_inline_script_json_escapes_script_terminators():
    value = "https://jira.example/create?next=</script>&project=SEC"

    assert _inline_script_json(value) == (
        '"https://jira.example/create?next=\\u003c/script\\u003e'
        '\\u0026project=SEC"'
    )


def test_render_index_html_replaces_frontend_runtime_config(tmp_path):
    index_path = tmp_path / "index.html"
    index_path.write_text(
        "|".join(
            [
                "${DTVP_CONTEXT_PATH}",
                "${DTVP_FRONTEND_URL}",
                "${DTVP_DEV_DISABLE_AUTH}",
                "${DTVP_DEFAULT_PROJECT_FILTER}",
                "${DTVP_ATTRIBUTION_AGE_FILTER_DAYS}",
                "'${DTVP_JIRA_CREATE_URL}'",
            ]
        ),
        encoding="utf-8",
    )

    response = _render_index_html(
        str(index_path),
        FrontendRouteDeps(
            frontend_dist_dir=str(tmp_path),
            get_context_path=lambda: "/ctx",
            get_frontend_url=lambda: "https://frontend.example",
            get_dev_disable_auth=lambda: True,
            get_default_project_filter=lambda: "Platform",
            get_attribution_age_filter_days=lambda: "5d,10d",
            get_jira_create_url=lambda: "https://jira.example/secure/CreateIssue!default.jspa",
            read_text=lambda path: index_path.read_text(encoding="utf-8"),
        ),
    )

    assert response.body.decode() == (
        '/ctx|https://frontend.example|true|Platform|5d,10d|'
        '"https://jira.example/secure/CreateIssue!default.jspa"'
    )


def test_context_path_frontend_routes_redirect_root_to_context(tmp_path):
    (tmp_path / "index.html").write_text("index", encoding="utf-8")
    app = FastAPI()

    register_frontend_routes(
        app,
        FrontendRouteDeps(
            frontend_dist_dir=str(tmp_path),
            get_context_path=lambda: "/dtvp-stage",
            get_frontend_url=lambda: "https://frontend.example",
            get_dev_disable_auth=lambda: False,
            get_default_project_filter=lambda: "",
            get_attribution_age_filter_days=lambda: "7d,14d,28d",
            get_jira_create_url=lambda: "",
            read_text=lambda path: (tmp_path / "index.html").read_text(
                encoding="utf-8"
            ),
        ),
    )

    with TestClient(app) as client:
        response = client.get("/", follow_redirects=False)

    assert response.status_code == 200
    assert "/dtvp-stage/" in response.text
