import json
import os
from dataclasses import dataclass
from html import escape
from typing import Callable

from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles


@dataclass(frozen=True)
class FrontendRouteDeps:
    frontend_dist_dir: str
    get_context_path: Callable[[], str]
    get_frontend_url: Callable[[], str]
    get_dev_disable_auth: Callable[[], bool]
    get_default_project_filter: Callable[[], str]
    get_attribution_age_filter_days: Callable[[], str]
    get_jira_create_url: Callable[[], str]
    read_text: Callable[[str], str]


def _inline_script_json(value: str) -> str:
    """Return a JSON string that cannot terminate the surrounding script tag."""
    return (
        json.dumps(value)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _render_index_html(index_path: str, deps: FrontendRouteDeps) -> HTMLResponse:
    try:
        content = deps.read_text(index_path)

        frontend_url = deps.get_frontend_url() or ""
        current_context_path = deps.get_context_path()

        content = content.replace("${DTVP_CONTEXT_PATH}", current_context_path or "/")
        content = content.replace("${DTVP_FRONTEND_URL}", frontend_url)
        content = content.replace(
            "${DTVP_DEV_DISABLE_AUTH}",
            "true" if deps.get_dev_disable_auth() else "false",
        )
        content = content.replace(
            "${DTVP_DEFAULT_PROJECT_FILTER}",
            deps.get_default_project_filter(),
        )
        content = content.replace(
            "${DTVP_ATTRIBUTION_AGE_FILTER_DAYS}",
            deps.get_attribution_age_filter_days(),
        )
        content = content.replace(
            "'${DTVP_JIRA_CREATE_URL}'",
            _inline_script_json(deps.get_jira_create_url()),
        )

        if current_context_path:
            content = content.replace('src="/', f'src="{current_context_path}/')
            content = content.replace('href="/', f'href="{current_context_path}/')

        return HTMLResponse(content)
    except Exception as exc:
        return HTMLResponse(
            f"Frontend not found or error loading: {str(exc)}",
            status_code=404,
        )


def _serve_spa_path(
    frontend_dist_dir: str,
    index_path: str,
    deps: FrontendRouteDeps,
    path: str,
):
    if ".." in path:
        return _render_index_html(index_path, deps)

    file_path = os.path.join(frontend_dist_dir, path)
    if path and os.path.isfile(file_path):
        return FileResponse(file_path)

    return _render_index_html(index_path, deps)


def register_frontend_routes(app: FastAPI, deps: FrontendRouteDeps) -> None:
    if not os.path.isdir(deps.frontend_dist_dir):
        return

    context_path = deps.get_context_path()
    assets_dir = os.path.join(deps.frontend_dist_dir, "assets")
    index_path = os.path.join(deps.frontend_dist_dir, "index.html")

    if context_path:

        @app.get("/", include_in_schema=False)
        async def redirect_root_to_context_path():
            target = f"{context_path}/"
            escaped_target = escape(target, quote=True)
            target_json = json.dumps(target)
            return HTMLResponse(
                f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="refresh" content="0; url={escaped_target}" />
  <title>DTVP</title>
</head>
<body>
  <script>window.location.replace({target_json});</script>
  <a href="{escaped_target}">DTVP</a>
</body>
</html>"""
            )

        @app.get(context_path)
        async def redirect_to_context_path():
            return RedirectResponse(url=f"{context_path}/")

    if os.path.isdir(assets_dir):
        app.mount(
            f"{context_path}/assets",
            StaticFiles(directory=assets_dir),
            name="assets",
        )

    if context_path:

        @app.get(context_path + "/{path:path}")
        async def serve_spa(path: str):
            return _serve_spa_path(deps.frontend_dist_dir, index_path, deps, path)

    else:

        @app.get("/{path:path}")
        async def serve_spa(path: str):
            return _serve_spa_path(deps.frontend_dist_dir, index_path, deps, path)
