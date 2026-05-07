import os
import tomllib
from datetime import datetime, timezone
from typing import Any, Optional

from .dt_cache import (
    get_knowledge_store_write_queue_warning_age_seconds,
    get_knowledge_store_write_queue_warning_threshold,
    get_pending_update_warning_age_seconds,
    get_pending_update_warning_threshold,
)
from .file_io_services import read_text
from .runtime_value_services import parse_iso_timestamp
from .startup_services import (
    get_knowledge_store_maintenance_warning_age_seconds,
    get_knowledge_store_orphan_warning_threshold,
)


def load_pyproject_metadata(cwd: Optional[str] = None) -> dict[str, Any]:
    root_dir = cwd or os.getcwd()
    pyproject_file = os.path.join(root_dir, "pyproject.toml")
    if not os.path.exists(pyproject_file):
        return {}
    with open(pyproject_file, "rb") as file_handle:
        data = tomllib.load(file_handle)
    project = data.get("project", {})
    return {
        "name": project.get("name"),
        "version": project.get("version"),
        "authors": project.get("authors", []),
        "urls": project.get("urls", {}),
    }


def load_changelog_content(cwd: Optional[str] = None) -> str:
    root_dir = cwd or os.getcwd()
    changelog_path = os.path.join(root_dir, "CHANGELOG.md")
    if not os.path.exists(changelog_path):
        return "Changelog not available."
    return read_text(changelog_path)


def get_sbom_path(filename: str, cwd: Optional[str] = None) -> Optional[str]:
    root_dir = cwd or os.getcwd()
    sbom_path = os.path.join(root_dir, "sbom", filename)
    if not os.path.exists(sbom_path):
        return None
    return sbom_path


def build_sbom_html(content: str) -> str:
    return (
        "<html><head><title>DTVP SBOM</title></head>"
        "<body><h1>DTVP CycloneDX SBOM</h1>"
        "<p><a href='/api/sbom'>Download JSON</a></p>"
        f"<pre>{content}</pre></body></html>"
    )


def _build_backlog_check(
    *,
    name: str,
    count: Any,
    oldest_age_seconds: Any,
    count_threshold: int,
    age_threshold_seconds: int,
    remediation: str,
) -> dict[str, Any]:
    backlog_count = int(count or 0)
    backlog_age = None if oldest_age_seconds is None else float(oldest_age_seconds)
    is_warning = backlog_count >= count_threshold or (
        backlog_age is not None and backlog_age >= age_threshold_seconds
    )
    is_critical = False
    if is_warning and count_threshold > 0 and backlog_count >= count_threshold * 3:
        is_critical = True
    if (
        is_warning
        and not is_critical
        and age_threshold_seconds > 0
        and backlog_age is not None
        and backlog_age >= age_threshold_seconds * 3
    ):
        is_critical = True
    return {
        "name": name,
        "status": "warning" if is_warning else "ok",
        "severity": "critical" if is_critical else ("warning" if is_warning else "ok"),
        "remediation": remediation,
        "count": backlog_count,
        "count_threshold": count_threshold,
        "oldest_age_seconds": backlog_age,
        "age_threshold_seconds": age_threshold_seconds,
    }


def _build_threshold_check(
    *,
    name: str,
    count: int,
    count_threshold: int,
    remediation: str,
) -> dict[str, Any]:
    is_warning = count >= count_threshold
    is_critical = is_warning and count_threshold > 0 and count >= count_threshold * 3
    return {
        "name": name,
        "status": "warning" if is_warning else "ok",
        "severity": "critical" if is_critical else ("warning" if is_warning else "ok"),
        "remediation": remediation,
        "count": count,
        "count_threshold": count_threshold,
    }


def _build_maintenance_freshness_check(
    *,
    last_maintenance_at: str | None,
    age_seconds: float | None,
    age_threshold_seconds: int,
    remediation: str,
) -> dict[str, Any]:
    is_warning = age_seconds is None or age_seconds >= age_threshold_seconds
    is_critical = age_seconds is None or (
        age_threshold_seconds > 0
        and age_seconds is not None
        and age_seconds >= age_threshold_seconds * 3
    )
    return {
        "name": "knowledge_store_maintenance_freshness",
        "status": "warning" if is_warning else "ok",
        "severity": "critical" if is_critical else ("warning" if is_warning else "ok"),
        "remediation": remediation,
        "last_maintenance_at": last_maintenance_at,
        "age_seconds": age_seconds,
        "age_threshold_seconds": age_threshold_seconds,
    }


def build_operational_health_summary(
    cache_status: dict[str, Any],
    knowledge_store_status: dict[str, Any],
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    last_maintenance_at = knowledge_store_status.get("last_maintenance_at")
    last_maintenance_timestamp = parse_iso_timestamp(last_maintenance_at)
    maintenance_age_seconds = None
    if last_maintenance_timestamp is not None:
        maintenance_age_seconds = max(0.0, now.timestamp() - last_maintenance_timestamp)

    maintenance_threshold = get_knowledge_store_maintenance_warning_age_seconds()
    orphan_threshold = get_knowledge_store_orphan_warning_threshold()
    orphaned_assessment_records = int(
        knowledge_store_status.get("orphaned_assessment_records") or 0
    )

    checks = {
        "pending_updates_backlog": _build_backlog_check(
            name="pending_updates_backlog",
            count=cache_status.get("pending_updates"),
            oldest_age_seconds=cache_status.get("pending_updates_oldest_age_seconds"),
            count_threshold=get_pending_update_warning_threshold(),
            age_threshold_seconds=get_pending_update_warning_age_seconds(),
            remediation="Let the pending Dependency-Track updates drain, or reduce incoming churn if the backlog keeps growing.",
        ),
        "knowledge_store_write_backlog": _build_backlog_check(
            name="knowledge_store_write_backlog",
            count=cache_status.get("knowledge_store_write_queue_size"),
            oldest_age_seconds=cache_status.get(
                "knowledge_store_write_queue_oldest_age_seconds"
            ),
            count_threshold=get_knowledge_store_write_queue_warning_threshold(),
            age_threshold_seconds=get_knowledge_store_write_queue_warning_age_seconds(),
            remediation="Check the knowledge-store writer and local disk health, then allow queued writes to flush.",
        ),
        "knowledge_store_orphans": _build_threshold_check(
            name="knowledge_store_orphans",
            count=orphaned_assessment_records,
            count_threshold=orphan_threshold,
            remediation="Run knowledge-store maintenance and verify active project synchronization removed stale retained assessments.",
        ),
        "knowledge_store_maintenance_freshness": _build_maintenance_freshness_check(
            last_maintenance_at=last_maintenance_at,
            age_seconds=maintenance_age_seconds,
            age_threshold_seconds=maintenance_threshold,
            remediation="Run knowledge-store maintenance and confirm the maintenance loop can complete successfully.",
        ),
    }
    overall_status = (
        "warning"
        if any(check["status"] == "warning" for check in checks.values())
        else "ok"
    )
    overall_severity = "ok"
    if any(check["severity"] == "critical" for check in checks.values()):
        overall_severity = "critical"
    elif overall_status == "warning":
        overall_severity = "warning"
    return {
        "status": overall_status,
        "severity": overall_severity,
        "checked_at": now.isoformat(),
        "checks": checks,
    }
