import asyncio
from dataclasses import dataclass, field
from typing import Any


def _startup_state() -> dict[str, Any]:
    return {
        "status": "ready",
        "message": "DTVP is ready.",
        "error": None,
    }


@dataclass
class DTVPRuntimeState:
    """Process-local state owned by the DTVP composition root."""

    background_tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    startup: dict[str, Any] = field(default_factory=_startup_state)
    grouped_tasks: dict[str, dict[str, Any]] = field(default_factory=dict)
    archive_tasks: dict[str, dict[str, Any]] = field(default_factory=dict)
    tmrescore_project_cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    tmrescore_analysis_tasks: dict[str, dict[str, Any]] = field(default_factory=dict)
