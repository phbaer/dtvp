"""Source connector contract and normalized snapshot envelope."""

from __future__ import annotations

from typing import Any, Protocol


class SourceConnector(Protocol):
    source_type: str

    async def discover_projects(self, client: Any) -> list[dict[str, Any]]:
        """Discover the complete current project catalog exposed by the source."""

    async def fetch_snapshot(self, client: Any, scope: dict[str, Any]) -> dict[str, Any]:
        """Fetch one complete source scope and normalize it to DTVP snapshot v1."""
