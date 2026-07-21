import time

from fastapi.testclient import TestClient

from dtvp import boot


def test_boot_serves_startup_page_before_real_app_import_finishes(monkeypatch):
    def slow_import(path=boot.REAL_APP_PATH):
        time.sleep(0.5)
        raise RuntimeError("delayed import")

    monkeypatch.setattr(boot, "_import_real_app", slow_import)
    app = boot.BootApp()

    with TestClient(app) as client:
        response = client.get("/")
        status_response = client.get("/api/startup")

    assert response.status_code == 200
    assert "DTVP is starting" in response.text
    assert status_response.status_code == 200
    assert status_response.json()["ready"] is False


def test_boot_returns_503_for_api_routes_before_real_app_is_ready(monkeypatch):
    def slow_import(path=boot.REAL_APP_PATH):
        time.sleep(0.5)
        raise RuntimeError("delayed import")

    monkeypatch.setattr(boot, "_import_real_app", slow_import)
    app = boot.BootApp()

    with TestClient(app) as client:
        response = client.get("/api/version")

    assert response.status_code == 503
    assert response.headers["retry-after"] == "2"
    assert response.json()["ready"] is False


def test_boot_exposes_liveness_but_not_readiness_while_loading(monkeypatch):
    def slow_import(path=boot.REAL_APP_PATH):
        time.sleep(0.5)
        raise RuntimeError("delayed import")

    monkeypatch.setattr(boot, "_import_real_app", slow_import)
    app = boot.BootApp()

    with TestClient(app) as client:
        live = client.get("/livez")
        ready = client.get("/readyz")

    assert live.status_code == 200
    assert live.json() == {"status": "alive"}
    assert ready.status_code == 503
    assert ready.json() == {"status": "not_ready"}


def test_boot_hands_http_to_real_app_after_import(monkeypatch):
    async def fake_app(scope, receive, send):
        body = b"real app"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    monkeypatch.setattr(boot, "_import_real_app", lambda path=boot.REAL_APP_PATH: fake_app)
    app = boot.BootApp()

    with TestClient(app) as client:
        response = client.get("/anything")
        deadline = time.monotonic() + 1
        while response.text != "real app" and time.monotonic() < deadline:
            time.sleep(0.02)
            response = client.get("/anything")

    assert response.status_code == 200
    assert response.text == "real app"
