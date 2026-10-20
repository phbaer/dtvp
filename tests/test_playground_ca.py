"""CA propagation without creating/resetting any playground services."""

import ssl
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import playground

CA = Path(__file__).parent / "fixtures/playground-build-ca.pem"
VARIABLES = (
    "DTVP_BUILD_CA",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)


@pytest.fixture(autouse=True)
def isolated_trust(monkeypatch):
    for name in VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: SimpleNamespace(cafile=None))


@pytest.mark.parametrize("variable", VARIABLES)
def test_selected_host_bundle_reaches_buildkit_and_node(monkeypatch, variable):
    monkeypatch.setenv(variable, str(CA))
    env = playground.build_environment()
    assert env["DTVP_BUILD_CA"] == str(CA.resolve())
    assert env["NODE_EXTRA_CA_CERTS"] == str(CA.resolve())


def test_default_host_store_and_explicit_override(monkeypatch, tmp_path):
    monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: SimpleNamespace(cafile=str(CA)))
    assert playground.build_environment()["DTVP_BUILD_CA"] == str(CA.resolve())
    monkeypatch.setenv("DTVP_BUILD_CA", str(tmp_path / "missing.pem"))
    assert playground.build_environment(str(CA))["DTVP_BUILD_CA"] == str(CA.resolve())


@pytest.mark.parametrize("contents", [None, "not a certificate"])
def test_invalid_selected_bundle_fails_before_docker(monkeypatch, tmp_path, contents):
    invalid = tmp_path / "invalid.pem"
    if contents is not None:
        invalid.write_text(contents)
    monkeypatch.setattr(sys, "argv", ["playground.py", "up", "--ca-cert", str(invalid)])
    calls = []
    monkeypatch.setattr(playground.subprocess, "run", lambda *a, **kw: calls.append(a))
    with pytest.raises(SystemExit) as error:
        playground.main()
    assert error.value.code == 2
    assert calls == []


@pytest.mark.parametrize("command", ["up", "reset", "test"])
def test_cli_propagates_bundle_to_compose_and_test_stack(monkeypatch, command):
    monkeypatch.setattr(sys, "argv", ["playground.py", command, "--ca-cert", str(CA)])
    calls = []
    monkeypatch.setattr(playground.subprocess, "run", lambda args, **kw: calls.append((args, kw)))
    monkeypatch.setattr(
        playground,
        "test_stack",
        lambda compose, skip, env: calls.append((compose, {"env": env})),
    )
    playground.main()
    assert calls
    for args, options in calls:
        assert str(playground.ROOT / "playground/compose.ca.yml") in args
        assert options["env"]["DTVP_BUILD_CA"] == str(CA.resolve())
        assert options["env"]["NODE_EXTRA_CA_CERTS"] == str(CA.resolve())


def test_no_host_bundle_keeps_standard_build_and_cleanup_ignores_bad_ca(monkeypatch):
    assert "DTVP_BUILD_CA" not in playground.build_environment()
    monkeypatch.setenv("DTVP_BUILD_CA", "/missing.pem")
    monkeypatch.setattr(sys, "argv", ["playground.py", "down"])
    calls = []
    monkeypatch.setattr(playground.subprocess, "run", lambda args, **kw: calls.append(args))
    playground.main()
    assert "down" in calls[0]
    assert str(playground.ROOT / "playground/compose.ca.yml") not in calls[0]


def test_host_test_downloads_keep_the_selected_ca(monkeypatch, tmp_path):
    (tmp_path / "frontend").mkdir()
    monkeypatch.setattr(playground, "ROOT", tmp_path)
    calls = []

    def run(args, **options):
        calls.append((args, options))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(playground.subprocess, "run", run)
    monkeypatch.setattr(playground.subprocess, "check_output", lambda *a, **kw: "127.0.0.1:12345")
    env = playground.build_environment(str(CA))
    playground.run_test_stack(["docker", "compose"], False, env)
    downloads = [(args, options) for args, options in calls if args[0] in {"npm", "npx", "uv"}]
    assert any(args[:2] == ["npm", "ci"] for args, _ in downloads)
    assert any(args[:3] == ["npx", "playwright", "install"] for args, _ in downloads)
    for _, options in downloads:
        assert options["env"]["NODE_EXTRA_CA_CERTS"] == str(CA.resolve())


def test_external_sources_are_explicit_validated_and_keep_demo_adapters():
    import json

    assert json.loads(playground.source_environment({})["DTVP_PLAYGROUND_PROVIDERS"]) == [
        "demo",
        "demo-failure",
    ]
    enabled = playground.source_environment({}, "osv,nvd,circl,euvd,jvn,osv")
    assert set(json.loads(enabled["DTVP_PLAYGROUND_PROVIDERS"])) == {
        "demo",
        "demo-failure",
        "osv",
        "nvd",
        "circl",
        "euvd",
        "jvn",
    }
    with pytest.raises(ValueError, match="Unknown external sources"):
        playground.source_environment({}, "dt")


def test_runtime_trust_and_live_sources_reach_compose_without_reading_production_env(monkeypatch):
    import json

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "playground.py",
            "up",
            "--skip-build",
            "--external-sources",
            "osv,nvd",
            "--runtime-ca-cert",
            str(CA),
        ],
    )
    calls = []
    monkeypatch.setattr(playground.subprocess, "run", lambda args, **kw: calls.append((args, kw)))
    playground.main()
    args, options = calls[0]
    assert args[args.index("--env-file") + 1] == "/dev/null"
    assert str(playground.ROOT / "playground/compose.runtime-ca.yml") in args
    assert set(json.loads(options["env"]["DTVP_PLAYGROUND_PROVIDERS"])) == {
        "demo",
        "demo-failure",
        "osv",
        "nvd",
    }
    assert options["env"]["DTVP_PLAYGROUND_RUNTIME_CA"] == str(CA.resolve())


def test_automatic_test_stack_ignores_live_provider_opt_in(monkeypatch):
    import json

    monkeypatch.setattr(sys, "argv", ["playground.py", "test", "--external-sources", "osv,nvd"])
    observed = []
    monkeypatch.setattr(playground, "test_stack", lambda compose, skip, env: observed.append(env))
    playground.main()
    assert json.loads(observed[0]["DTVP_PLAYGROUND_PROVIDERS"]) == ["demo", "demo-failure"]


def test_invalid_runtime_trust_fails_before_docker(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["playground.py", "up", "--runtime-ca-cert", "/missing.pem"])
    monkeypatch.setattr(
        playground.subprocess, "run", lambda *a, **kw: pytest.fail("Docker invoked")
    )
    with pytest.raises(SystemExit) as error:
        playground.main()
    assert error.value.code == 2
