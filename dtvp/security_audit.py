"""Structured security audit events for state-changing and denied requests."""

from __future__ import annotations

import contextvars
import fcntl
import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

logger = logging.getLogger("dtvp.security_audit")


@dataclass(frozen=True, slots=True)
class AuditRequestContext:
    request_id: str
    actor: str
    role: str
    remote_ip: str


_request_context: contextvars.ContextVar[AuditRequestContext | None] = (
    contextvars.ContextVar("dtvp_security_audit_context", default=None)
)
_health_guard = threading.Lock()
_write_guard = threading.Lock()
_last_write_error: str | None = None
_last_write_at: str | None = None


def _integer_setting(name: str, default: int, *, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def get_security_audit_max_bytes() -> int:
    return _integer_setting("DTVP_SECURITY_AUDIT_MAX_BYTES", 100 * 1024 * 1024)


def get_security_audit_backup_count() -> int:
    return _integer_setting("DTVP_SECURITY_AUDIT_BACKUP_COUNT", 10, minimum=1)


def set_audit_request_context(
    context: AuditRequestContext,
) -> contextvars.Token[AuditRequestContext | None]:
    return _request_context.set(context)


def reset_audit_request_context(
    token: contextvars.Token[AuditRequestContext | None],
) -> None:
    _request_context.reset(token)


def get_security_audit_path() -> str:
    configured = os.getenv("DTVP_SECURITY_AUDIT_PATH")
    if configured is not None:
        return configured.strip()
    if os.getenv("DTVP_ENVIRONMENT", "production").strip().lower() == "production":
        return "data/security_audit.jsonl"
    return ""


def _safe_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:2048]
    if isinstance(value, Mapping):
        return {
            str(key)[:128]: _safe_value(item)
            for key, item in list(value.items())[:64]
            if str(key).lower()
            not in {"authorization", "cookie", "password", "secret", "token", "api_key"}
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_value(item) for item in list(value)[:64]]
    return str(value)[:2048]


def _set_health(*, error: str | None, written_at: str | None = None) -> None:
    global _last_write_error, _last_write_at
    with _health_guard:
        _last_write_error = error
        if written_at is not None:
            _last_write_at = written_at


def audit_health() -> dict[str, Any]:
    path_text = get_security_audit_path()
    try:
        size_bytes = Path(path_text).stat().st_size if path_text else None
    except OSError:
        size_bytes = None
    with _health_guard:
        return {
            "configured": bool(path_text),
            "healthy": _last_write_error is None,
            "last_write_at": _last_write_at,
            "last_error": _last_write_error,
            "size_bytes": size_bytes,
            "max_bytes": get_security_audit_max_bytes(),
            "backup_count": get_security_audit_backup_count(),
        }


def _rotate_audit_file(path: Path, incoming_bytes: int) -> None:
    max_bytes = get_security_audit_max_bytes()
    if max_bytes <= 0 or not path.exists():
        return
    current_size = path.stat().st_size
    if current_size == 0 or current_size + incoming_bytes <= max_bytes:
        return

    backup_count = get_security_audit_backup_count()
    oldest = Path(f"{path}.{backup_count}")
    if oldest.exists():
        oldest.unlink()
    for index in range(backup_count - 1, 0, -1):
        source = Path(f"{path}.{index}")
        if source.exists():
            os.replace(source, Path(f"{path}.{index + 1}"))
    os.replace(path, Path(f"{path}.1"))


def validate_security_audit_configuration() -> None:
    """Fail production startup when the append-only audit target is unavailable."""
    path_text = get_security_audit_path()
    if not path_text:
        if os.getenv("DTVP_ENVIRONMENT", "production").lower() == "production":
            raise RuntimeError("DTVP_SECURITY_AUDIT_PATH is required in production")
        return
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def emit_security_audit(
    action: str,
    *,
    outcome: str,
    resource_type: str = "http_route",
    resource_id: str = "",
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Emit one JSON event to logging and the configured owner-only JSONL file."""
    context = _request_context.get()
    timestamp = datetime.now(UTC).isoformat()
    event: dict[str, Any] = {
        "schema": "dtvp.security-audit.v1",
        "timestamp": timestamp,
        "event_id": str(uuid.uuid4()),
        "request_id": context.request_id if context else "",
        "actor": context.actor if context else "system",
        "role": context.role if context else "SYSTEM",
        "remote_ip": context.remote_ip if context else "",
        "action": str(action)[:128],
        "resource_type": str(resource_type)[:128],
        "resource_id": str(resource_id)[:1024],
        "outcome": str(outcome)[:64],
        "details": _safe_value(details or {}),
    }
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    event["event_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    serialized = json.dumps(event, sort_keys=True, separators=(",", ":"))
    logger.info(serialized)

    path_text = get_security_audit_path()
    if not path_text:
        return event
    try:
        encoded = f"{serialized}\n".encode("utf-8")
        path = Path(path_text)
        with _write_guard:
            path.parent.mkdir(parents=True, exist_ok=True)
            _rotate_audit_file(path, len(encoded))
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                os.write(descriptor, encoded)
                if os.getenv("DTVP_SECURITY_AUDIT_FSYNC", "false").lower() in {
                    "1",
                    "true",
                    "yes",
                    "on",
                }:
                    os.fsync(descriptor)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        _set_health(error=None, written_at=timestamp)
    except OSError as exc:
        message = f"{exc.__class__.__name__}: {exc}"
        _set_health(error=message)
        logger.error("Security audit persistence failed: %s", message)
    return event
