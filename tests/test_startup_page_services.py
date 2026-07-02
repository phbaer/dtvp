from dtvp.startup_page_services import (
    build_startup_page_html,
    build_startup_status_payload,
    contextual_path,
)


def test_contextual_path_handles_root_and_context_paths():
    assert contextual_path("", "/api/startup") == "/api/startup"
    assert contextual_path("/dtvp", "api/startup") == "/dtvp/api/startup"


def test_startup_status_payload_reports_ready_state():
    payload = build_startup_status_payload(
        {"status": "ready", "message": "DTVP is ready."}
    )

    assert payload == {
        "status": "ready",
        "ready": True,
        "message": "DTVP is ready.",
    }


def test_startup_status_payload_hides_failure_details():
    payload = build_startup_status_payload(
        {"status": "failed", "message": "boom", "error": "secret path"}
    )

    assert payload["ready"] is False
    assert payload["status"] == "failed"
    assert payload["message"] == "DTVP startup failed. Check the backend logs."
    assert "secret" not in str(payload)


def test_startup_page_uses_contextual_status_endpoint():
    html = build_startup_page_html(
        state={"status": "starting", "message": "Preparing cache."},
        context_path="/dtvp",
    )

    assert "DTVP is starting" in html
    assert "Preparing cache." in html
    assert '"/dtvp/api/startup"' in html
    assert '"/dtvp/"' in html
