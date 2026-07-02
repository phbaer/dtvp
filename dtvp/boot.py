import asyncio
import importlib
import json
import os
import traceback
from contextlib import AsyncExitStack
from typing import Any, Awaitable, Callable

from .startup_page_services import (
    build_startup_page_html,
    build_startup_status_payload,
    contextual_path,
)

ASGIReceive = Callable[[], Awaitable[dict[str, Any]]]
ASGISend = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[dict[str, Any], ASGIReceive, ASGISend], Awaitable[None]]

REAL_APP_PATH = os.getenv("DTVP_BOOT_APP", "dtvp.main:app")


def _normalize_context_path(raw_context_path: str | None) -> str:
    context_path = (raw_context_path or "/").rstrip("/")
    if context_path and not context_path.startswith("/"):
        context_path = "/" + context_path
    return "" if context_path == "/" else context_path


def _header_value(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    lower_name = name.lower()
    for key, value in headers:
        if key.lower() == lower_name:
            return value.decode("latin1")
    return None


def _default_allowed_origins() -> set[str]:
    origins = {
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
    }
    frontend_url = os.getenv("DTVP_FRONTEND_URL")
    if frontend_url:
        origins.add(frontend_url.rstrip("/"))
    cors_origins = os.getenv("DTVP_CORS_ORIGINS")
    if cors_origins:
        origins.update(
            origin.strip().rstrip("/")
            for origin in cors_origins.split(",")
            if origin.strip()
        )
    return origins


def _cors_headers(scope: dict[str, Any]) -> list[tuple[bytes, bytes]]:
    origin = _header_value(scope.get("headers", []), b"origin")
    if not origin or origin.rstrip("/") not in _default_allowed_origins():
        return []
    return [
        (b"access-control-allow-origin", origin.encode("latin1")),
        (b"access-control-allow-credentials", b"true"),
        (b"vary", b"Origin"),
    ]


def _import_real_app(path: str = REAL_APP_PATH) -> ASGIApp:
    module_name, _, attribute = path.partition(":")
    if not module_name or not attribute:
        raise RuntimeError(f"Invalid DTVP_BOOT_APP value: {path!r}")
    module = importlib.import_module(module_name)
    app = module
    for part in attribute.split("."):
        app = getattr(app, part)
    return app


class BootApp:
    def __init__(self) -> None:
        self.context_path = _normalize_context_path(os.getenv("DTVP_CONTEXT_PATH", "/"))
        self.state: dict[str, Any] = {
            "status": "starting",
            "message": "DTVP application is loading.",
            "error": None,
        }
        self.real_app: ASGIApp | None = None
        self._real_app_stack: AsyncExitStack | None = None
        self._load_task: asyncio.Task[None] | None = None

    def _ensure_load_started(self) -> None:
        if self._load_task is None:
            self._load_task = asyncio.create_task(self._load_real_app())

    def _set_state(
        self,
        status: str,
        message: str,
        error: str | None = None,
    ) -> None:
        self.state = {
            "status": status,
            "message": message,
            "error": error,
        }

    def _is_startup_path(self, path: str) -> bool:
        return path in {
            contextual_path(self.context_path, "/startup"),
            contextual_path(self.context_path, "/api/startup"),
        }

    def _is_startup_page_path(self, path: str) -> bool:
        return path == contextual_path(self.context_path, "/startup")

    def _is_api_or_auth_path(self, path: str) -> bool:
        return any(
            path == prefix or path.startswith(f"{prefix}/")
            for prefix in (
                contextual_path(self.context_path, "/api"),
                contextual_path(self.context_path, "/auth"),
            )
        )

    async def _load_real_app(self) -> None:
        try:
            self._set_state("starting", "DTVP application is loading.")
            real_app = await asyncio.to_thread(_import_real_app)
            stack = AsyncExitStack()
            lifespan_context = getattr(
                getattr(real_app, "router", None),
                "lifespan_context",
                None,
            )
            if lifespan_context is not None:
                await stack.enter_async_context(lifespan_context(real_app))
            self._real_app_stack = stack
            self.real_app = real_app
            self._set_state("ready", "DTVP is ready.")
        except asyncio.CancelledError:
            self._set_state("stopped", "DTVP startup was stopped.")
            raise
        except Exception as exc:
            traceback.print_exc()
            self._set_state(
                "failed",
                "DTVP startup failed. Check the backend logs.",
                str(exc),
            )

    async def _handle_lifespan(self, receive: ASGIReceive, send: ASGISend) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
                self._ensure_load_started()
            elif message["type"] == "lifespan.shutdown":
                if self._load_task and not self._load_task.done():
                    self._load_task.cancel()
                    try:
                        await self._load_task
                    except asyncio.CancelledError:
                        pass
                if self._real_app_stack is not None:
                    await self._real_app_stack.aclose()
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _send_response(
        self,
        scope: dict[str, Any],
        receive: ASGIReceive,
        send: ASGISend,
        *,
        status_code: int,
        body: bytes,
        media_type: str,
        extra_headers: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        await _drain_request_body(receive)
        headers = [
            (b"content-type", media_type.encode("latin1")),
            (b"cache-control", b"no-store"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        headers.extend(_cors_headers(scope))
        if extra_headers:
            headers.extend(extra_headers)
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": headers,
            }
        )
        method = scope.get("method", "GET").upper()
        await send(
            {
                "type": "http.response.body",
                "body": b"" if method == "HEAD" else body,
            }
        )

    async def _send_startup_status(
        self,
        scope: dict[str, Any],
        receive: ASGIReceive,
        send: ASGISend,
        *,
        status_code: int = 200,
    ) -> None:
        body = json.dumps(build_startup_status_payload(self.state)).encode("utf-8")
        await self._send_response(
            scope,
            receive,
            send,
            status_code=status_code,
            body=body,
            media_type="application/json",
            extra_headers=[(b"retry-after", b"2")] if status_code == 503 else None,
        )

    async def _send_startup_page(
        self,
        scope: dict[str, Any],
        receive: ASGIReceive,
        send: ASGISend,
    ) -> None:
        body = build_startup_page_html(
            state=self.state,
            context_path=self.context_path,
        ).encode("utf-8")
        await self._send_response(
            scope,
            receive,
            send,
            status_code=200,
            body=body,
            media_type="text/html; charset=utf-8",
        )

    async def _send_options_response(
        self,
        scope: dict[str, Any],
        receive: ASGIReceive,
        send: ASGISend,
    ) -> None:
        await _drain_request_body(receive)
        headers = [
            (b"access-control-allow-methods", b"GET,HEAD,OPTIONS"),
            (b"access-control-allow-headers", b"*"),
            (b"access-control-max-age", b"600"),
            (b"content-length", b"0"),
        ]
        headers.extend(_cors_headers(scope))
        await send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": b""})

    async def _handle_http(
        self,
        scope: dict[str, Any],
        receive: ASGIReceive,
        send: ASGISend,
    ) -> None:
        path = scope.get("path", "")
        if self.real_app is not None:
            await self.real_app(scope, receive, send)
            return

        self._ensure_load_started()

        if scope.get("method", "").upper() == "OPTIONS":
            await self._send_options_response(scope, receive, send)
        elif self._is_startup_page_path(path):
            await self._send_startup_page(scope, receive, send)
        elif self._is_startup_path(path):
            await self._send_startup_status(scope, receive, send)
        elif self._is_api_or_auth_path(path):
            await self._send_startup_status(
                scope,
                receive,
                send,
                status_code=503,
            )
        else:
            await self._send_startup_page(scope, receive, send)

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: ASGIReceive,
        send: ASGISend,
    ) -> None:
        if scope["type"] == "lifespan":
            await self._handle_lifespan(receive, send)
        elif scope["type"] == "http":
            await self._handle_http(scope, receive, send)
        elif self.real_app is not None:
            await self.real_app(scope, receive, send)
        else:
            await send({"type": "websocket.close", "code": 1013})


async def _drain_request_body(receive: ASGIReceive) -> None:
    while True:
        message = await receive()
        if message["type"] != "http.request" or not message.get("more_body", False):
            return


app = BootApp()
