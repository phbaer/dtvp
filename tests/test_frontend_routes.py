from fastapi import FastAPI
from fastapi.testclient import TestClient

from dtvp.frontend_routes import (
    FrontendRouteDeps,
    _inline_script_json,
    _render_index_html,
    _runtime_config_javascript,
    register_frontend_routes,
)


def test_inline_script_json_escapes_script_terminators():
    value = "https://jira.example/create?next=</script>&project=SEC"

    assert _inline_script_json(value) == (
        '"https://jira.example/create?next=\\u003c/script\\u003e'
        '\\u0026project=SEC"'
    )


def test_runtime_config_javascript_escapes_untrusted_values(tmp_path):
    script = _runtime_config_javascript(
        FrontendRouteDeps(
            frontend_dist_dir=str(tmp_path),
            get_context_path=lambda: "/ctx",
            get_frontend_url=lambda: "https://frontend.example/</script>",
            get_dev_disable_auth=lambda: True,
            get_default_project_filter=lambda: "Platform",
            get_attribution_age_filter_days=lambda: "5d,10d",
            get_jira_create_url=lambda: "https://jira.example/?next=</script>",
            read_text=lambda path: "",
        )
    )

    assert script.startswith("window.__env__ = {")
    assert "</script>" not in script
    assert "\\u003c/script\\u003e" in script
    assert '"DTVP_DEV_DISABLE_AUTH": "true"' in script


def test_render_index_html_rewrites_same_origin_asset_paths(tmp_path):
    index_path = tmp_path / "index.html"
    index_path.write_text(
        '<script src="/runtime-config.js"></script>'
        '<script type="module" src="/assets/app.js"></script>',
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
        '<script src="/ctx/runtime-config.js"></script>'
        '<script type="module" src="/ctx/assets/app.js"></script>'
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
        runtime_config = client.get("/dtvp-stage/runtime-config.js")

    assert response.status_code == 307
    assert response.headers["location"] == "/dtvp-stage/"
    assert runtime_config.status_code == 200
    assert runtime_config.headers["cache-control"] == "no-store"
    assert "window.__env__" in runtime_config.text
