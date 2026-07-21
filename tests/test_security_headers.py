from starlette.responses import Response

from dtvp.security_headers import CONTENT_SECURITY_POLICY, add_security_headers


def test_security_headers_include_browser_isolation_in_production():
    response = Response()

    add_security_headers(response, production=True)

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert "script-src 'self'" in response.headers["content-security-policy"]
    script_policy = response.headers["content-security-policy"].split(
        "script-src", 1
    )[1].split(";", 1)[0]
    assert "unsafe-inline" not in script_policy
    assert response.headers["strict-transport-security"].startswith(
        "max-age=31536000"
    )


def test_development_headers_do_not_break_interactive_tooling():
    response = Response()

    add_security_headers(response, production=False)

    assert "content-security-policy" not in response.headers
    assert "strict-transport-security" not in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"
