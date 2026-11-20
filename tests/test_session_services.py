import time

import pytest
from jose import jwt

from dtvp.session_services import (
    SessionClaims,
    SessionConfig,
    SessionConfigError,
    SessionSettings,
    decode_session_token,
    issue_session_token,
    load_session_config,
    needs_refresh,
)

VALID_KEY = "k" * 32


def settings(**values):
    return SessionSettings(_env_file=None, **values)


def refused(**values) -> str:
    with pytest.raises(SessionConfigError) as exc:
        load_session_config(settings(**values))
    return str(exc.value)


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    # conftest sets a valid key for the app; these tests pass their own.
    for name in (
        "DTVP_SESSION_SECRET_KEY",
        "DTVP_SESSION_SECRET_KEY_FILE",
        "DTVP_SESSION_TTL_HOURS",
        "DTVP_SESSION_MAX_AGE_HOURS",
        "DTVP_SESSION_ALLOW_DEV_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


# --- signing key -----------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["change_me", "", "   ", "x" * 31, "  change_me\n"],
    ids=["placeholder", "empty", "blank", "31-bytes", "padded-placeholder"],
)
def test_weak_or_missing_key_is_refused_with_a_generation_hint(key):
    message = refused(DTVP_SESSION_SECRET_KEY=key)

    assert "DTVP_SESSION_SECRET_KEY" in message
    assert "secrets.token_urlsafe" in message
    assert "openssl rand" in message
    if key.strip():
        assert key.strip() not in message.replace("'change_me'", "")


def test_unset_key_is_refused():
    message = refused()
    assert "DTVP_SESSION_SECRET_KEY is not set." in message


def test_short_key_reports_its_length_but_not_its_value():
    key = "abcdefghij0123456789ABCDEFGHIJK"  # 31 bytes
    message = refused(DTVP_SESSION_SECRET_KEY=key)
    assert "is 31 bytes long; at least 32 are required" in message
    assert key not in message


def test_placeholder_is_named():
    assert "the placeholder 'change_me'" in refused(DTVP_SESSION_SECRET_KEY="change_me")


@pytest.mark.parametrize("key", ["a" * 32, "é" * 16], ids=["ascii", "utf8"])
def test_key_of_32_bytes_is_accepted(key):
    config = load_session_config(settings(DTVP_SESSION_SECRET_KEY=key))
    assert config.secret_key == key


def test_key_is_stripped():
    config = load_session_config(settings(DTVP_SESSION_SECRET_KEY=f"  {VALID_KEY}\n"))
    assert config.secret_key == VALID_KEY


def test_key_is_read_from_the_file_without_its_trailing_newline(tmp_path):
    path = tmp_path / "session.key"
    path.write_text(f"{VALID_KEY}\n", encoding="utf-8")

    config = load_session_config(settings(DTVP_SESSION_SECRET_KEY_FILE=str(path)))

    assert config.secret_key == VALID_KEY


def test_missing_key_file_is_refused(tmp_path):
    path = tmp_path / "missing.key"
    message = refused(DTVP_SESSION_SECRET_KEY_FILE=str(path))

    assert "DTVP_SESSION_SECRET_KEY_FILE points to" in message
    assert "cannot be read" in message
    assert "secrets.token_urlsafe" in message


def test_empty_key_file_is_refused(tmp_path):
    path = tmp_path / "empty.key"
    path.write_text("\n", encoding="utf-8")
    assert "DTVP_SESSION_SECRET_KEY_FILE" in refused(
        DTVP_SESSION_SECRET_KEY_FILE=str(path)
    )


def test_placeholder_or_short_key_in_the_file_is_refused_naming_the_file_variable(
    tmp_path,
):
    path = tmp_path / "session.key"
    path.write_text("change_me\n", encoding="utf-8")
    message = refused(DTVP_SESSION_SECRET_KEY_FILE=str(path))
    assert "DTVP_SESSION_SECRET_KEY_FILE is the placeholder" in message

    path.write_text("short-key", encoding="utf-8")
    message = refused(DTVP_SESSION_SECRET_KEY_FILE=str(path))
    assert "DTVP_SESSION_SECRET_KEY_FILE is 9 bytes long" in message
    assert "short-key" not in message


def test_key_and_key_file_together_are_refused(tmp_path):
    path = tmp_path / "session.key"
    path.write_text(VALID_KEY, encoding="utf-8")
    message = refused(
        DTVP_SESSION_SECRET_KEY=VALID_KEY, DTVP_SESSION_SECRET_KEY_FILE=str(path)
    )
    assert "Set either DTVP_SESSION_SECRET_KEY or DTVP_SESSION_SECRET_KEY_FILE" in message
    assert VALID_KEY not in message


def test_environment_is_read(monkeypatch):
    monkeypatch.setenv("DTVP_SESSION_SECRET_KEY", "change_me")
    with pytest.raises(SessionConfigError):
        load_session_config(SessionSettings(_env_file=None))

    # No development or test switch relaxes the check.
    monkeypatch.setenv("DTVP_DEV_DISABLE_AUTH", "true")
    with pytest.raises(SessionConfigError):
        load_session_config(SessionSettings(_env_file=None))


def test_config_repr_does_not_reveal_the_key():
    config = SessionConfig(secret_key=VALID_KEY, ttl_seconds=3600)
    assert VALID_KEY not in repr(config)
    assert VALID_KEY not in str(config)


# --- lifetime --------------------------------------------------------------


def test_default_lifetime_is_twelve_hours():
    config = load_session_config(settings(DTVP_SESSION_SECRET_KEY=VALID_KEY))
    assert config.ttl_seconds == 12 * 3600


def test_lifetime_is_configurable():
    config = load_session_config(
        settings(DTVP_SESSION_SECRET_KEY=VALID_KEY, DTVP_SESSION_TTL_HOURS="6")
    )
    assert config.ttl_seconds == 6 * 3600


@pytest.mark.parametrize("hours", ["0", "-1", "abc", "721", "1.5"])
def test_invalid_lifetime_is_refused(hours):
    message = refused(DTVP_SESSION_SECRET_KEY=VALID_KEY, DTVP_SESSION_TTL_HOURS=hours)
    assert "DTVP_SESSION_TTL_HOURS must be a whole number of hours between 1 and 720" in message


# --- session tokens --------------------------------------------------------

CONFIG = SessionConfig(secret_key=VALID_KEY, ttl_seconds=12 * 3600)


def signed(claims, key=VALID_KEY):
    return jwt.encode(claims, key, algorithm="HS256")


def test_token_roundtrip_carries_type_user_version_and_lifetime():
    now = 1_800_000_000
    token = issue_session_token(CONFIG, "alice", 3, now=now)

    claims = jwt.decode(
        token, VALID_KEY, algorithms=["HS256"], options={"verify_exp": False}
    )
    assert claims == {
        "typ": "dtvp-session",
        "sub": "alice",
        "ver": 3,
        "iat": now,
        "exp": now + 12 * 3600,
        "auth_time": now,
    }


def test_decode_returns_the_claims_of_a_valid_token():
    now = int(time.time())
    token = issue_session_token(CONFIG, "alice", 2, now=now)

    assert decode_session_token(CONFIG, token) == SessionClaims(
        username="alice", version=2, issued_at=now, expires_at=now + 12 * 3600,
        authenticated_at=now,
    )


def _now():
    return int(time.time())


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(
            lambda: signed(
                {
                    "typ": "dtvp-session",
                    "sub": "alice",
                    "ver": 0,
                    "iat": _now() - 7200,
                    "exp": _now() - 3600,
                }
            ),
            id="expired",
        ),
        pytest.param(lambda: signed({"sub": "alice"}), id="legacy"),
        pytest.param(
            lambda: signed(
                {"typ": "dtvp-session", "sub": "alice", "iat": _now(), "exp": _now() + 60}
            ),
            id="missing-ver",
        ),
        pytest.param(
            lambda: signed(
                {
                    "typ": "dtvp-session",
                    "sub": "alice",
                    "ver": True,
                    "iat": _now(),
                    "exp": _now() + 60,
                }
            ),
            id="bool-ver",
        ),
        pytest.param(
            lambda: signed(
                {
                    "typ": "dtvp-session",
                    "sub": "alice",
                    "ver": -1,
                    "iat": _now(),
                    "exp": _now() + 60,
                }
            ),
            id="negative-ver",
        ),
        pytest.param(
            lambda: signed(
                {
                    "typ": "other",
                    "sub": "alice",
                    "ver": 0,
                    "iat": _now(),
                    "exp": _now() + 60,
                }
            ),
            id="wrong-typ",
        ),
        pytest.param(
            lambda: signed(
                {
                    "typ": "dtvp-session",
                    "sub": "",
                    "ver": 0,
                    "iat": _now(),
                    "exp": _now() + 60,
                }
            ),
            id="empty-sub",
        ),
        pytest.param(
            lambda: signed(
                {
                    "typ": "dtvp-session",
                    "sub": "alice",
                    "ver": 0,
                    "iat": _now(),
                    "exp": _now(),
                }
            ),
            id="exp-not-after-iat",
        ),
        pytest.param(
            lambda: issue_session_token(
                SessionConfig(secret_key="o" * 32, ttl_seconds=3600), "alice", 0
            ),
            id="other-key",
        ),
        pytest.param(
            lambda: jwt.encode(
                {
                    "typ": "dtvp-session",
                    "sub": "alice",
                    "ver": 0,
                    "iat": _now(),
                    "exp": _now() + 60,
                },
                VALID_KEY,
                algorithm="HS512",
            ),
            id="other-algorithm",
        ),
        pytest.param(
            lambda: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJ0eXAiOiJkdHZwLXNlc3Npb24iLCJzdWIiOiJhbGljZSIsInZlciI6MH0.",
            id="alg-none",
        ),
        pytest.param(lambda: "not-a-token", id="garbage"),
        pytest.param(lambda: "", id="empty"),
    ],
)
def test_decode_rejects(token):
    assert decode_session_token(CONFIG, token()) is None


def test_decode_rejects_an_ssvc_evidence_token(monkeypatch):
    from dtvp import auth
    from dtvp.ssvc_enrichment_services import sign_evidence

    monkeypatch.setattr(auth, "session_config", CONFIG)
    token = sign_evidence({"value": "N"})

    assert jwt.decode(token, VALID_KEY, algorithms=["HS256"])["purpose"]
    assert decode_session_token(CONFIG, token) is None


def test_needs_refresh_after_half_the_lifetime():
    claims = SessionClaims(
        "alice", 0, issued_at=1000, expires_at=1000 + 3600, authenticated_at=1000
    )

    assert needs_refresh(claims, now=1000) is False
    assert needs_refresh(claims, now=1000 + 1800) is False
    assert needs_refresh(claims, now=1000 + 1801) is True


# -- absolute session lifetime ------------------------------------------------

CAPPED = SessionConfig(secret_key=VALID_KEY, ttl_seconds=12 * 3600, max_age_seconds=24 * 3600)


def test_renewal_never_extends_a_session_past_the_maximum_age():
    signed_in = int(time.time()) - 20 * 3600
    # A renewal 20 h after sign-in: 12 h more would pass the 24 h cap.
    token = issue_session_token(CAPPED, "alice", 0, authenticated_at=signed_in)
    claims = decode_session_token(CAPPED, token)

    assert claims is not None
    assert claims.authenticated_at == signed_in
    assert claims.expires_at == signed_in + 24 * 3600
    # Renewing again cannot help: the token already ends at the cap.
    assert needs_refresh(claims, now=claims.expires_at - 1, config=CAPPED) is False


def test_a_token_past_the_maximum_age_is_rejected_even_before_its_exp():
    now = int(time.time())
    # Signed under a longer maximum age, then the maximum was lowered.
    longer = SessionConfig(secret_key=VALID_KEY, ttl_seconds=12 * 3600, max_age_seconds=48 * 3600)
    token = issue_session_token(longer, "alice", 0, now=now - 3600, authenticated_at=now - 30 * 3600)

    assert decode_session_token(longer, token) is not None
    assert decode_session_token(CAPPED, token) is None


def test_a_token_without_a_sign_in_time_is_rejected():
    now = int(time.time())
    token = signed({"typ": "dtvp-session", "sub": "alice", "ver": 0, "iat": now, "exp": now + 3600})

    assert decode_session_token(CONFIG, token) is None


def test_the_maximum_age_is_configurable_and_not_below_the_lifetime():
    key = {"DTVP_SESSION_SECRET_KEY": VALID_KEY}
    assert load_session_config(settings(**key)).max_age_seconds == 168 * 3600
    assert load_session_config(
        settings(**key, DTVP_SESSION_MAX_AGE_HOURS="24")
    ).max_age_seconds == 24 * 3600
    for bad in ("0", "11", "soon", "9999"):
        assert "DTVP_SESSION_MAX_AGE_HOURS" in refused(**key, DTVP_SESSION_MAX_AGE_HOURS=bad)


# -- committed development keys ------------------------------------------------


def test_a_committed_development_key_needs_the_development_flag():
    key = "dtvp-dev-only-" + "x" * 32

    message = refused(DTVP_SESSION_SECRET_KEY=key, DTVP_SESSION_ALLOW_DEV_KEY=False)
    assert "DTVP_SESSION_ALLOW_DEV_KEY" in message and key not in message
    assert load_session_config(
        settings(DTVP_SESSION_SECRET_KEY=key, DTVP_SESSION_ALLOW_DEV_KEY=True)
    ).secret_key == key
