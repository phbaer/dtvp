from typing import Any, Callable


def build_cors_origins(
    auth_settings: Any,
    cors_from_env: str | None,
    get_hostname: Callable[[], str],
) -> list[str]:
    if cors_from_env:
        return [origin.strip() for origin in cors_from_env.split(",") if origin.strip()]

    origins = [
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
    ]

    if auth_settings.FRONTEND_URL:
        frontend_url = auth_settings.FRONTEND_URL.rstrip("/")
        if frontend_url not in origins:
            origins.append(frontend_url)

    try:
        hostname = get_hostname()
        for port in ("5173", "8000"):
            origin = f"http://{hostname}:{port}"
            if origin not in origins:
                origins.append(origin)
    except Exception:
        pass

    return origins


def normalize_context_path(raw_context_path: str) -> str:
    context_path = raw_context_path.rstrip("/")
    if context_path and not context_path.startswith("/"):
        context_path = "/" + context_path
    return context_path
