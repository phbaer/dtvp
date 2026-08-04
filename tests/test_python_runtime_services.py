import pytest

from dtvp import python_runtime_services


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "on"])
def test_free_threading_requirement_accepts_true_values(value):
    assert python_runtime_services.free_threading_is_required(
        {"DTVP_REQUIRE_FREE_THREADED": value}
    )


@pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "off"])
def test_free_threading_requirement_accepts_false_values(value):
    assert not python_runtime_services.free_threading_is_required(
        {"DTVP_REQUIRE_FREE_THREADED": value}
    )


def test_free_threading_requirement_rejects_ambiguous_values():
    with pytest.raises(RuntimeError, match="DTVP_REQUIRE_FREE_THREADED"):
        python_runtime_services.free_threading_is_required(
            {"DTVP_REQUIRE_FREE_THREADED": "sometimes"}
        )


def test_runtime_status_reports_active_free_threading(monkeypatch):
    monkeypatch.setattr(
        python_runtime_services.sysconfig,
        "get_config_var",
        lambda name: 1 if name == "Py_GIL_DISABLED" else None,
    )
    monkeypatch.setattr(
        python_runtime_services.sys,
        "_is_gil_enabled",
        lambda: False,
    )

    status = python_runtime_services.get_python_runtime_status(
        {"DTVP_REQUIRE_FREE_THREADED": "true"}
    )

    assert status["free_threaded_build"] is True
    assert status["gil_enabled"] is False
    assert status["free_threading_active"] is True
    assert status["free_threading_required"] is True


def test_required_free_threading_rejects_standard_build(monkeypatch):
    monkeypatch.setattr(
        python_runtime_services.sysconfig,
        "get_config_var",
        lambda _name: 0,
    )

    with pytest.raises(RuntimeError, match="built with the GIL"):
        python_runtime_services.validate_python_runtime(
            {"DTVP_REQUIRE_FREE_THREADED": "true"}
        )


def test_required_free_threading_rejects_runtime_gil(monkeypatch):
    monkeypatch.setattr(
        python_runtime_services.sysconfig,
        "get_config_var",
        lambda _name: 1,
    )
    monkeypatch.setattr(
        python_runtime_services.sys,
        "_is_gil_enabled",
        lambda: True,
    )

    with pytest.raises(RuntimeError, match="GIL is enabled"):
        python_runtime_services.validate_python_runtime(
            {"DTVP_REQUIRE_FREE_THREADED": "true"}
        )


def test_standard_runtime_remains_supported_when_not_required(monkeypatch):
    monkeypatch.setattr(
        python_runtime_services.sysconfig,
        "get_config_var",
        lambda _name: 0,
    )
    monkeypatch.setattr(
        python_runtime_services.sys,
        "_is_gil_enabled",
        lambda: True,
    )

    status = python_runtime_services.validate_python_runtime({})

    assert status["free_threading_active"] is False
    assert status["free_threading_required"] is False
