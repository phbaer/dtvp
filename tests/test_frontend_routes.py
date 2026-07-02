from dtvp.frontend_routes import FrontendRouteDeps, _render_index_html


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
            read_text=lambda path: index_path.read_text(encoding="utf-8"),
        ),
    )

    assert response.body.decode() == "/ctx|https://frontend.example|true|Platform|5d,10d"
