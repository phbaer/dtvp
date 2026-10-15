import json
import sys

import httpx
import respx

from dtvp.cli import main


@respx.mock
def test_machine_workspace_cli_uses_http_without_opening_database(monkeypatch, capsys):
    import dtvp.cli as cli

    monkeypatch.setenv("TEST_DTVP_TOKEN", "machine-test-token")
    monkeypatch.setattr(
        cli, "Settings", lambda: (_ for _ in ()).throw(AssertionError("No database"))
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "--token-env",
            "TEST_DTVP_TOKEN",
            "workspace",
            "--project",
            "project",
            "--version",
            "7.1.1",
        ],
    )
    route = respx.get("http://dtvp.test/api/v3/projects/project/versions/7.1.1/workspace").mock(
        return_value=httpx.Response(
            200,
            json={
                "state": "a" * 64,
                "statistics": {"totals": {"context_findings": 1}, "approved": 1, "submitted": 1},
                "items": [
                    {
                        "vulnerability_id": "CVE-test",
                        "component": {"name": "library", "version": "1"},
                        "context": {"root_ref": "app", "team_id": "team"},
                        "coverage": {"status": "approved"},
                        "source_ratings": [{"score": 9.8}],
                        "published_score": {"score": 0, "current": True},
                    }
                ],
                "next_offset": None,
            },
        )
    )
    main()
    assert route.calls[0].request.headers["authorization"] == "Bearer machine-test-token"
    output = capsys.readouterr().out
    assert "source=9.8 contextual=0" in output
    assert "machine-test-token" not in output


@respx.mock
def test_playground_cli_forwards_json_and_csrf_without_domain_logic(monkeypatch, tmp_path, capsys):
    payload = {"request_id": "explicit-request", "expected_versions": {"7.1.1": "b" * 64}}
    body = tmp_path / "review.json"
    body.write_text(json.dumps(payload))
    respx.post("http://dtvp.test/api/v2/playground/login").mock(
        return_value=httpx.Response(
            200, json={}, headers={"Set-Cookie": "dtvp_csrf=csrf-test; Path=/"}
        )
    )
    route = respx.post("http://dtvp.test/api/v3/projects/project/reviews").mock(
        return_value=httpx.Response(201, json={"committed": True})
    )
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "--persona",
            "reviewer",
            "request",
            "POST",
            "/api/v3/projects/project/reviews",
            "--body",
            str(body),
        ],
    )
    main()
    assert json.loads(route.calls[0].request.content) == payload
    assert route.calls[0].request.headers["x-csrf-token"] == "csrf-test"
    assert json.loads(capsys.readouterr().out)["committed"] is True
