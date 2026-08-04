import os
import platform
import sys
import sysconfig
from collections.abc import Mapping
from typing import Any


_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def free_threading_is_required(
    environ: Mapping[str, str] | None = None,
) -> bool:
    values = os.environ if environ is None else environ
    raw_value = values.get("DTVP_REQUIRE_FREE_THREADED", "false")
    normalized = raw_value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise RuntimeError(
        "DTVP_REQUIRE_FREE_THREADED must be one of "
        "true/false, 1/0, yes/no, or on/off"
    )


def get_python_runtime_status(
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    free_threaded_build = sysconfig.get_config_var("Py_GIL_DISABLED") == 1
    gil_state_getter = getattr(sys, "_is_gil_enabled", None)
    gil_enabled = (
        bool(gil_state_getter()) if callable(gil_state_getter) else None
    )
    return {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "free_threaded_build": free_threaded_build,
        "gil_enabled": gil_enabled,
        "free_threading_active": free_threaded_build and gil_enabled is False,
        "free_threading_required": free_threading_is_required(environ),
    }


def validate_python_runtime(
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    status = get_python_runtime_status(environ)
    if not status["free_threading_required"]:
        return status
    if not status["free_threaded_build"]:
        raise RuntimeError(
            "DTVP requires a free-threaded CPython build, but this interpreter "
            "was built with the GIL. Use the 3.14t deployment variant."
        )
    if status["gil_enabled"] is not False:
        raise RuntimeError(
            "DTVP requires free-threaded execution, but the GIL is enabled. "
            "Check PYTHON_GIL and imported native extensions."
        )
    return status
