"""The shipped configurations keep the session key check satisfiable.

Compose must not fall back to the refused placeholder. Every development
setup (pm2 ecosystem, the documented split-backend exports, VS Code) carries
a committed key DTVP accepts only as a development key: copied into
production without the development flag, it is refused.
"""

import json
import re
from pathlib import Path

import pytest

from dtvp.session_services import (
    DEV_KEY_PREFIX,
    SessionConfigError,
    SessionSettings,
    load_session_config,
)

ROOT = Path(__file__).resolve().parents[1]


def _accepted(key: str) -> None:
    """A committed key works in development and is refused anywhere else."""
    assert key.startswith(DEV_KEY_PREFIX)
    config = load_session_config(
        SessionSettings(
            _env_file=None, DTVP_SESSION_SECRET_KEY=key, DTVP_SESSION_ALLOW_DEV_KEY=True
        )
    )
    assert config.secret_key == key
    # The test process itself runs with the flag set; production does not.
    with pytest.raises(SessionConfigError, match="development key"):
        load_session_config(
            SessionSettings(
                _env_file=None, DTVP_SESSION_SECRET_KEY=key, DTVP_SESSION_ALLOW_DEV_KEY=False
            )
        )


def test_compose_requires_a_session_key_instead_of_a_placeholder():
    compose = (ROOT / "compose.yml").read_text()

    assert "DTVP_SESSION_SECRET_KEY: ${DTVP_SESSION_SECRET_KEY:-}" in compose
    assert "DTVP_SESSION_SECRET_KEY_FILE: ${DTVP_SESSION_SECRET_KEY_FILE:-}" in compose
    assert "DTVP_SESSION_SECRET_KEY:-change_me" not in compose


def test_pm2_development_backend_has_an_accepted_session_key():
    ecosystem = (ROOT / "ecosystem.config.js").read_text()
    match = re.search(r'DTVP_SESSION_SECRET_KEY:\s*"([^"]+)"', ecosystem)

    assert match is not None
    _accepted(match.group(1))
    assert 'DTVP_SESSION_ALLOW_DEV_KEY: "true"' in ecosystem


def test_documented_split_backend_exports_an_accepted_session_key():
    development = (ROOT / "docs" / "development.md").read_text()
    match = re.search(r"^export DTVP_SESSION_SECRET_KEY=(\S+)$", development, re.M)

    assert match is not None
    _accepted(match.group(1))
    assert re.search(r"^export DTVP_SESSION_ALLOW_DEV_KEY=true$", development, re.M)


def test_vscode_launch_configuration_has_an_accepted_session_key():
    launch = json.loads((ROOT / ".vscode" / "launch.json").read_text())

    for configuration in launch["configurations"]:
        if "dtvp.main:app" not in configuration.get("args", []):
            continue
        env = configuration.get("env") or {}
        _accepted(env["DTVP_SESSION_SECRET_KEY"])
        assert env["DTVP_SESSION_ALLOW_DEV_KEY"] == "true"


def test_the_test_suite_uses_a_development_key():
    conftest = (ROOT / "tests" / "conftest.py").read_text()
    match = re.search(r'os.environ\["DTVP_SESSION_SECRET_KEY"\] = "([^"]+)"', conftest)

    assert match is not None
    _accepted(match.group(1))
