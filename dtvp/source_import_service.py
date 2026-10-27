"""Shared orchestration for durable, source-neutral inventory imports."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from copy import deepcopy
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .artifact_store import ArtifactStore
from .catalog_repository import (
    begin_import_run,
    ensure_source_connection,
    fail_import_run,
    publish_snapshot,
    sync_source_catalog_projects,
)
from .source_connectors.base import SourceConnector

logger = logging.getLogger(__name__)


def _safe_base_url(raw_url: str) -> str:
    parsed = urlsplit(raw_url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("Source connector has an invalid base URL")
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path.rstrip("/"), "", ""))


def _safe_error_summary(error: Exception) -> str:
    if isinstance(error, httpx.HTTPStatusError):
        return f"Source returned HTTP {error.response.status_code}"
    if isinstance(error, httpx.TimeoutException):
        return "Source request timed out"
    if isinstance(error, LookupError):
        return str(error)[:1000]
    if isinstance(error, ValueError):
        return str(error)[:1000]
    if isinstance(error, TimeoutError):
        return "Source request timed out"
    return f"Source import failed ({type(error).__name__})"


def _state_sha256(snapshot: dict[str, Any]) -> str:
    """Fingerprint normalized state without per-run timestamps or raw captures."""
    state = deepcopy(snapshot)
    state.pop("captured_at", None)
    state.pop("source_artifacts", None)
    provenance = state.get("provenance")
    if isinstance(provenance, dict):
        provenance.pop("captured_at", None)
    security = state.get("security")
    if isinstance(security, dict):
        for finding in security.get("findings", []) or []:
            if isinstance(finding, dict):
                attribution = finding.get("attribution")
                if isinstance(attribution, dict):
                    attribution.pop("observed_at", None)
    return hashlib.sha256(ArtifactStore.encode_json(state)).hexdigest()


async def discover_source_projects(
    *,
    connector: SourceConnector,
    client: Any,
    source_base_url: str,
) -> list[dict[str, Any]]:
    """Discover a complete provider catalog and persist its DTVP-owned view."""
    normalized_base_url = _safe_base_url(source_base_url)
    source_connection_id = await asyncio.to_thread(
        ensure_source_connection,
        source_type=connector.source_type,
        display_name=f"{connector.source_type} ({normalized_base_url})",
        config={"base_url": normalized_base_url, "connector_version": 1},
        secret_ref="env:DTVP_DT_API_KEY" if connector.source_type == "dependency-track" else None,
    )
    discovered = await connector.discover_projects(client)
    return await asyncio.to_thread(
        sync_source_catalog_projects,
        source_connection_id=source_connection_id,
        projects=discovered,
    )


async def import_source_scope(
    *,
    connector: SourceConnector,
    client: Any,
    source_base_url: str,
    request_id: str,
    initiated_by: str,
    scope: dict[str, Any],
    artifact_store: ArtifactStore | None = None,
) -> dict[str, Any]:
    """Fetch, normalize, retain, and atomically publish one source snapshot."""
    normalized_base_url = _safe_base_url(source_base_url)
    source_connection_id = await asyncio.to_thread(
        ensure_source_connection,
        source_type=connector.source_type,
        display_name=f"{connector.source_type} ({normalized_base_url})",
        config={"base_url": normalized_base_url, "connector_version": 1},
        secret_ref="env:DTVP_DT_API_KEY" if connector.source_type == "dependency-track" else None,
    )
    run, created = await asyncio.to_thread(
        begin_import_run,
        source_connection_id=source_connection_id,
        request_id=request_id,
        scope=scope,
        initiated_by=initiated_by,
    )
    if not created:
        return run

    try:
        snapshot = await connector.fetch_snapshot(client, scope)
        if snapshot.get("schema") != "dtvp.inventory-snapshot/v1":
            raise ValueError("Connector returned an unsupported DTVP snapshot schema")
        captured_at = datetime.fromisoformat(snapshot["captured_at"])
        product_name = str(snapshot["product"].get("name") or "").strip()
        version_name = str(snapshot["version"].get("name") or "").strip()
        provenance = snapshot.get("provenance") or {}
        source_product_id = str(provenance.get("source_product_id") or "").strip()
        source_version_id = str(provenance.get("source_version_id") or "").strip()
        if not product_name:
            raise ValueError("Normalized snapshot is missing its product name")
        if not source_product_id:
            raise ValueError("Normalized snapshot is missing its source product identity")
        if not source_version_id:
            raise ValueError("Normalized snapshot is missing its source version identity")

        store = artifact_store or ArtifactStore()
        payload_sha256 = await asyncio.to_thread(store.put_json, snapshot)
        state_sha256 = _state_sha256(snapshot)
        inventory = snapshot.get("inventory") or {}
        security = snapshot.get("security") or {}
        counts = {
            "components": len(inventory.get("components") or []),
            "dependencies": len(inventory.get("dependencies") or []),
            "findings": len(security.get("findings") or []),
            "advisories": len(security.get("advisories") or []),
        }
        return await asyncio.to_thread(
            publish_snapshot,
            run_id=run["id"],
            source_connection_id=source_connection_id,
            source_product_id=source_product_id,
            source_version_id=source_version_id,
            payload_sha256=payload_sha256,
            state_sha256=state_sha256,
            captured_at=captured_at,
            snapshot_counts=counts,
            product_name=product_name,
            version_name=version_name,
        )
    except Exception as exc:
        logger.exception("Source import failed (run_id=%s)", run["id"])
        summary = _safe_error_summary(exc)
        try:
            return await asyncio.to_thread(fail_import_run, run["id"], summary)
        except Exception:
            logger.exception("Could not persist source import failure (run_id=%s)", run["id"])
            raise
