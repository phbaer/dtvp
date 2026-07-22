import json
import os
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Optional

from .sqlite_migration_services import run_sqlite_migrations


CODE_ANALYSIS_RESULT_SCHEMA_VERSION = "dtvp.code-analysis-result/v1"
CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE = "code_analysis_results"
CODE_ANALYSIS_ASSESSMENT_METADATA_VERSION = 1
FOLLOW_UP_CONTEXT_PROMPT_LIMIT = 12_000


def get_code_analysis_results_path() -> str:
    configured_path = os.getenv("DTVP_CODE_ANALYSIS_RESULTS_PATH", "").strip()
    if configured_path:
        return configured_path
    return os.path.join(os.getcwd(), "data", "code_analysis_results.sqlite")


def get_code_analysis_result_migrations_path() -> Path:
    return Path(__file__).resolve().parent / "migrations" / "code_analysis_results"


def get_code_analysis_results_max_records() -> int:
    raw_value = os.getenv("DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS", "2000")
    try:
        return max(1, int(raw_value))
    except (TypeError, ValueError):
        return 2000


def get_code_analysis_results_retention_days() -> int:
    raw_value = os.getenv("DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS", "0")
    try:
        return max(0, int(raw_value))
    except (TypeError, ValueError):
        return 0


def get_code_analysis_results_store_guidance() -> bool:
    raw_value = os.getenv("DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE", "true")
    return raw_value.strip().lower() not in {"0", "false", "no", "off", "disabled"}


def get_code_analysis_result_freshness_days() -> int:
    raw_value = os.getenv("DTVP_CODE_ANALYSIS_RESULT_FRESHNESS_DAYS", "0")
    try:
        return max(0, int(raw_value))
    except (TypeError, ValueError):
        return 0


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump"):
        dumped = value.model_dump()
        return dumped if isinstance(dumped, dict) else {}
    if hasattr(value, "dict"):
        dumped = value.dict()
        return dumped if isinstance(dumped, dict) else {}
    return {}


def _compact_text(value: Any, limit: int = 1600) -> str:
    text = _normalize_text(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()}..."


def _parse_timestamp(value: Any) -> Optional[datetime]:
    text = _normalize_text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _record_timestamp(record: dict[str, Any]) -> Optional[datetime]:
    for key in ("finished_at", "recorded_at", "started_at", "submitted_at"):
        parsed = _parse_timestamp(record.get(key))
        if parsed:
            return parsed.astimezone(UTC)
    return None


def _record_within_freshness(record: dict[str, Any], freshness_days: int = 0) -> bool:
    if freshness_days <= 0:
        return True
    timestamp = _record_timestamp(record)
    if not timestamp:
        return False
    return timestamp >= datetime.now(UTC) - timedelta(days=freshness_days)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_ready(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_json_ready(inner) for inner in value]
    if isinstance(value, tuple):
        return [_json_ready(inner) for inner in value]
    return _enum_value(value)


def _load_records_from_path(path: str, logger: Any = None) -> dict[str, dict[str, Any]]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        if logger:
            logger.warning("Failed to load code-analysis results from %s: %s", path, exc)
        return {}

    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        raw_records = payload["records"]
    elif isinstance(payload, list):
        raw_records = payload
    else:
        raw_records = []

    records: dict[str, dict[str, Any]] = {}
    for record in raw_records:
        if not isinstance(record, dict):
            continue
        run_id = _normalize_text(
            record.get("analysis_run_id")
            or record.get("run_id")
            or record.get("queue_id")
        )
        if not run_id:
            continue
        record["analysis_run_id"] = run_id
        records[run_id] = record
    return records


def _sqlite_path_for_configured_path(path: str) -> str:
    parsed = Path(path)
    if parsed.suffix.lower() == ".json":
        return str(parsed.with_suffix(".sqlite"))
    return path


def _legacy_json_path_for_configured_path(path: str) -> str:
    parsed = Path(path)
    if parsed.suffix.lower() == ".json":
        return str(parsed)
    return str(parsed.with_suffix(".json"))


def _record_timestamp_text(record: dict[str, Any]) -> str:
    timestamp = _record_timestamp(record)
    return timestamp.isoformat() if timestamp else ""


def _record_payload_json(record: dict[str, Any]) -> str:
    return json.dumps(_json_ready(record), sort_keys=True, separators=(",", ":"))


def _decode_record_payload(payload: str, logger: Any = None) -> Optional[dict[str, Any]]:
    try:
        value = json.loads(payload)
    except Exception as exc:
        if logger:
            logger.warning("Failed to decode code-analysis result payload: %s", exc)
        return None
    return value if isinstance(value, dict) else None


def _decode_json_dict(value: Any) -> dict[str, Any]:
    try:
        decoded = json.loads(str(value or "{}"))
    except (TypeError, ValueError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _decode_json_strings(value: Any) -> list[str]:
    try:
        decoded = json.loads(str(value or "[]"))
    except (TypeError, ValueError):
        return []
    if not isinstance(decoded, list):
        return []
    return list(
        dict.fromkeys(
            normalized
            for item in decoded
            if (normalized := _lower(item))
        )
    )


def _build_record_assessment_metadata(record: dict[str, Any]) -> dict[str, Any]:
    # Imported lazily to keep result serialization independent during module load.
    from .code_analysis_assessment_services import build_record_assessment_metadata

    return build_record_assessment_metadata(record)


def summarize_code_analysis_result(result: Any) -> dict[str, Any]:
    result_dict = _as_dict(result)
    assessment = _as_dict(result_dict.get("assessment"))
    adjusted_cvss = _as_dict(assessment.get("adjusted_cvss"))
    component_results = [
        {
            "component": _normalize_text(component_result.get("component")),
            "verdict": _normalize_text(
                _as_dict(component_result.get("assessment")).get("verdict")
            ),
            "confidence": _normalize_text(
                _as_dict(component_result.get("assessment")).get("confidence")
            ),
            "exposure": _normalize_text(
                _as_dict(component_result.get("assessment")).get("exposure")
            ),
            "versions_checked": [
                _normalize_text(version)
                for version in component_result.get("versions_checked", [])
                if _normalize_text(version)
            ],
        }
        for component_result in (result_dict.get("component_results") or [])
        if isinstance(component_result, dict)
    ]

    return {
        "affected": assessment.get("affected"),
        "verdict": _normalize_text(assessment.get("verdict")),
        "confidence": _normalize_text(assessment.get("confidence")),
        "exposure": _normalize_text(assessment.get("exposure")),
        "analysis": _normalize_text(assessment.get("analysis")),
        "justification": _normalize_text(assessment.get("justification")),
        "response": _normalize_text(assessment.get("response")),
        "summary": _normalize_text(assessment.get("summary")),
        "reasoning": _normalize_text(assessment.get("reasoning")),
        "details": _normalize_text(assessment.get("details")),
        "cvss_score": assessment.get("cvss_score"),
        "cvss_vector": assessment.get("cvss_vector"),
        "original_cvss_score": adjusted_cvss.get("original_score"),
        "original_cvss_vector": adjusted_cvss.get("original_vector"),
        "adjusted_cvss_score": adjusted_cvss.get("adjusted_score"),
        "adjusted_cvss_vector": adjusted_cvss.get("adjusted_vector"),
        "cvss_summary": _normalize_text(adjusted_cvss.get("summary")),
        "cvss_reasons": list(adjusted_cvss.get("reasons") or []),
        "versions_checked": [
            _normalize_text(version)
            for version in (result_dict.get("versions_checked") or [])
            if _normalize_text(version)
        ],
        "component_results": component_results,
        "step_count": len(result_dict.get("steps") or []),
    }


def build_compact_analysis_context(record: dict[str, Any]) -> dict[str, Any]:
    result = _as_dict(record.get("result"))
    assessment = _as_dict(result.get("assessment"))
    summary = _as_dict(record.get("summary")) or summarize_code_analysis_result(result)
    steps = []
    for step in result.get("steps") or []:
        if not isinstance(step, dict):
            continue
        evidence = step.get("evidence") or []
        findings = step.get("findings")
        steps.append(
            {
                "step": step.get("step"),
                "title": _compact_text(step.get("title"), 240),
                "status": step.get("status"),
                "findings": _compact_findings(findings),
                "evidence": (
                    [_compact_text(entry, 600) for entry in evidence[:5]]
                    if isinstance(evidence, list)
                    else []
                ),
            }
        )

    return {
        "schema_version": "dtvp.code-analysis-compact-context/v1",
        "compacted_at": _utc_now_iso(),
        "analysis_run_id": record.get("analysis_run_id"),
        "queue_id": record.get("queue_id"),
        "job_id": record.get("job_id"),
        "target": {
            "project_name": record.get("project_name"),
            "vuln_id": record.get("vuln_id"),
            "component_name": record.get("component_name"),
        },
        "request_context": {
            "context_fingerprint": record.get("context_fingerprint"),
            "context_summary": record.get("context_summary"),
            "cvss_vector": record.get("cvss_vector"),
            "source": record.get("source"),
            "follow_up_question": record.get("follow_up_question"),
        },
        "verdict": {
            "affected": summary.get("affected"),
            "verdict": summary.get("verdict"),
            "confidence": summary.get("confidence"),
            "exposure": summary.get("exposure"),
            "analysis": summary.get("analysis"),
            "justification": summary.get("justification"),
            "response": summary.get("response"),
        },
        "summary": _compact_text(summary.get("summary"), 1600),
        "reasoning": _compact_text(summary.get("reasoning"), 2400),
        "details": _compact_text(summary.get("details"), 2400),
        "cvss": {
            "original_score": summary.get("original_cvss_score"),
            "original_vector": summary.get("original_cvss_vector"),
            "adjusted_score": summary.get("adjusted_cvss_score"),
            "adjusted_vector": summary.get("adjusted_cvss_vector"),
            "summary": _compact_text(summary.get("cvss_summary"), 1200),
            "reasons": [
                _compact_text(reason, 400)
                for reason in (summary.get("cvss_reasons") or [])[:8]
            ],
        },
        "versions_checked": summary.get("versions_checked") or [],
        "component_results": summary.get("component_results") or [],
        "dependency_presence": _compact_mapping(assessment.get("dependency_presence")),
        "advisory_relevance": _compact_mapping(assessment.get("advisory_relevance")),
        "version_analysis": _compact_mapping(assessment.get("version_analysis")),
        "researcher_view": _compact_mapping(assessment.get("researcher_view")),
        "remediation_view": _compact_mapping(assessment.get("remediation_view")),
        "audit_view": _compact_mapping(assessment.get("audit_view")),
        "steps": steps,
        "uncertainty": {
            "confidence": summary.get("confidence"),
            "gaps": _extract_compact_gaps(assessment),
        },
    }


def _extract_compact_gaps(assessment: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    audit_view = _as_dict(assessment.get("audit_view"))
    if audit_view.get("conclusion"):
        gaps.append(_normalize_text(audit_view.get("conclusion")))
    remediation_view = _as_dict(assessment.get("remediation_view"))
    recommendations = remediation_view.get("recommendations")
    if isinstance(recommendations, list):
        gaps.extend(_normalize_text(item) for item in recommendations if _normalize_text(item))
    return gaps[:8]


def _compact_mapping(value: Any, *, max_text: int = 800) -> Any:
    if isinstance(value, dict):
        compacted: dict[str, Any] = {}
        for key, inner in value.items():
            if isinstance(inner, (dict, list)):
                compacted[str(key)] = _compact_mapping(inner, max_text=max_text)
            elif isinstance(inner, str):
                compacted[str(key)] = _compact_text(inner, max_text)
            else:
                compacted[str(key)] = inner
        return compacted
    if isinstance(value, list):
        return [_compact_mapping(inner, max_text=max_text) for inner in value[:12]]
    if isinstance(value, str):
        return _compact_text(value, max_text)
    return value


def _compact_findings(value: Any) -> Any:
    if value is None:
        return None
    return _compact_mapping(value, max_text=500)


def build_follow_up_guidance(
    parent_record: dict[str, Any],
    question: str,
    *,
    extra_guidance: Optional[str] = None,
) -> str:
    context = (
        parent_record.get("compact_context")
        if isinstance(parent_record.get("compact_context"), dict)
        else build_compact_analysis_context(parent_record)
    )
    pretty_context = _compact_text(
        json.dumps(context, indent=2, sort_keys=True),
        FOLLOW_UP_CONTEXT_PROMPT_LIMIT,
    )
    lines = [
        "DTVP follow-up analysis. Reuse the compact prior context below as background; do not treat it as proof if new code evidence contradicts it.",
        "",
        "Follow-up question:",
        question.strip(),
        "",
        "Compact prior context:",
        pretty_context,
    ]
    if extra_guidance and extra_guidance.strip():
        lines.extend(["", "Additional reviewer guidance:", extra_guidance.strip()])
    return "\n".join(lines)


def _redact_prompt_trace(result: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(result)
    for key in ("llm_conversation", "llm_trace", "conversation", "prompt_context"):
        redacted.pop(key, None)
    return redacted


def build_code_analysis_result_record(
    item: Any,
    *,
    result: dict[str, Any],
    recorded_at: Optional[str] = None,
) -> dict[str, Any]:
    item_data = item.model_dump(exclude={"result"}) if hasattr(item, "model_dump") else dict(getattr(item, "__dict__", {}))
    item_data = _json_ready(item_data)
    result = _json_ready(result)
    store_guidance = get_code_analysis_results_store_guidance()
    if not store_guidance:
        result = _redact_prompt_trace(result)
    summary = summarize_code_analysis_result(result)
    run_id = _normalize_text(item_data.get("queue_id"))
    record = {
        "schema_version": CODE_ANALYSIS_RESULT_SCHEMA_VERSION,
        "analysis_run_id": run_id,
        "queue_id": item_data.get("queue_id"),
        "job_id": item_data.get("job_id"),
        "parent_run_id": item_data.get("parent_run_id"),
        "parent_job_id": item_data.get("parent_job_id"),
        "follow_up_question": item_data.get("follow_up_question"),
        "context_mode": item_data.get("context_mode"),
        "project_name": item_data.get("project_name"),
        "vuln_id": item_data.get("vuln_id"),
        "component_name": item_data.get("component_name"),
        "source": item_data.get("source") or "manual",
        "submitted_by": item_data.get("submitted_by"),
        "submitted_at": item_data.get("submitted_at"),
        "started_at": item_data.get("started_at"),
        "finished_at": item_data.get("finished_at") or recorded_at or _utc_now_iso(),
        "status": item_data.get("status") or "completed",
        "model": item_data.get("model"),
        "llm_backend": item_data.get("llm_backend"),
        "llm_provider": item_data.get("llm_provider"),
        "llm_metadata": item_data.get("llm_metadata"),
        "cvss_vector": item_data.get("cvss_vector"),
        "context_fingerprint": item_data.get("context_fingerprint"),
        "context_summary": item_data.get("context_summary"),
        "user_guidance": (
            item_data.get("user_guidance")
            if store_guidance
            else None
        ),
        "follow_up_user_guidance": (
            item_data.get("follow_up_user_guidance")
            if store_guidance
            else None
        ),
        "user_guidance_redacted": not store_guidance,
        "summary": summary,
        "result": result,
        "recorded_at": recorded_at or _utc_now_iso(),
    }
    record["compact_context"] = build_compact_analysis_context(record)
    return record


@dataclass
class CodeAnalysisResultStore:
    path_provider: Callable[[], str] = get_code_analysis_results_path
    logger: Any = None
    _loaded_path: Optional[str] = field(default=None, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _assessment_metadata_cache: Optional[dict[str, Any]] = field(
        default=None,
        init=False,
    )

    def reset(self) -> None:
        with self._lock:
            self._loaded_path = None
            self._assessment_metadata_cache = None

    def _path(self) -> str:
        return _sqlite_path_for_configured_path(self.path_provider())

    def _legacy_json_path(self) -> str:
        return _legacy_json_path_for_configured_path(self.path_provider())

    def _connect(self) -> sqlite3.Connection:
        path = self._path()
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(path, timeout=5)
        run_sqlite_migrations(
            connection,
            namespace=CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE,
            migrations_path=get_code_analysis_result_migrations_path(),
            logger=self.logger,
        )
        return connection

    def _ensure_loaded(self) -> None:
        path = self._path()
        if self._loaded_path == path:
            return
        self._assessment_metadata_cache = None
        with closing(self._connect()) as connection:
            with connection:
                self._import_legacy_json_locked(connection)
                self._backfill_assessment_metadata_locked(connection)
                self._prune_locked(connection)
        self._loaded_path = path

    def _invalidate_assessment_metadata_cache_locked(self) -> None:
        self._assessment_metadata_cache = None

    def _legacy_import_key(self, legacy_path: str) -> str:
        return f"legacy_json_imported:{os.path.abspath(legacy_path)}"

    def _import_legacy_json_locked(self, connection: sqlite3.Connection) -> None:
        legacy_path = self._legacy_json_path()
        if not legacy_path or not os.path.exists(legacy_path):
            return

        import_key = self._legacy_import_key(legacy_path)
        imported = connection.execute(
            "SELECT value FROM code_analysis_result_meta WHERE key = ?",
            (import_key,),
        ).fetchone()
        if imported:
            return

        records = _load_records_from_path(legacy_path, self.logger)
        for record in records.values():
            self._upsert_record_locked(connection, record)

        connection.execute(
            """
            INSERT OR REPLACE INTO code_analysis_result_meta (key, value)
            VALUES (?, ?)
            """,
            (import_key, _utc_now_iso()),
        )
        if records and self.logger:
            self.logger.info(
                "Imported %d legacy code-analysis result records from %s",
                len(records),
                legacy_path,
            )

    def _upsert_record_locked(
        self,
        connection: sqlite3.Connection,
        record: dict[str, Any],
    ) -> None:
        run_id = _normalize_text(
            record.get("analysis_run_id")
            or record.get("run_id")
            or record.get("queue_id")
        )
        if not run_id:
            return
        record["analysis_run_id"] = run_id
        assessment_metadata = _build_record_assessment_metadata(record)
        project_names = assessment_metadata.get("project_names") or []
        connection.execute(
            """
            INSERT OR REPLACE INTO code_analysis_results (
                analysis_run_id,
                project_name_lower,
                vuln_id_lower,
                component_name_lower,
                source_lower,
                context_fingerprint,
                finished_at,
                submitted_at,
                recorded_at,
                record_timestamp,
                payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                _lower(record.get("project_name"))
                or (project_names[0] if project_names else ""),
                _lower(record.get("vuln_id"))
                or _lower(assessment_metadata.get("vuln_id")),
                _lower(record.get("component_name"))
                or _lower(assessment_metadata.get("scan_target")),
                _lower(record.get("source")),
                _normalize_text(record.get("context_fingerprint")),
                _normalize_text(record.get("finished_at")),
                _normalize_text(record.get("submitted_at")),
                _normalize_text(record.get("recorded_at")),
                _record_timestamp_text(record),
                _record_payload_json(record),
            ),
        )
        self._upsert_assessment_metadata_locked(
            connection,
            run_id,
            assessment_metadata,
        )

    def _upsert_assessment_metadata_locked(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        metadata: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT OR REPLACE INTO code_analysis_assessment_metadata (
                analysis_run_id,
                metadata_version,
                has_assessment,
                vuln_id_lower,
                project_names_json,
                component_names_json,
                scan_target_lower,
                source_kind,
                assessment_data_json,
                record_data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                int(
                    metadata.get("metadata_version")
                    or CODE_ANALYSIS_ASSESSMENT_METADATA_VERSION
                ),
                1 if metadata.get("has_assessment") else 0,
                _lower(metadata.get("vuln_id")),
                json.dumps(
                    metadata.get("project_names") or [],
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                json.dumps(
                    metadata.get("component_names") or [],
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                _lower(metadata.get("scan_target")),
                _lower(metadata.get("source_kind")) or "unknown",
                json.dumps(
                    metadata.get("assessment") or {},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                json.dumps(
                    metadata.get("record") or {},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )

    def _backfill_assessment_metadata_locked(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        cursor = connection.execute(
            """
            SELECT results.analysis_run_id, results.payload_json
            FROM code_analysis_results AS results
            LEFT JOIN code_analysis_assessment_metadata AS metadata
              ON metadata.analysis_run_id = results.analysis_run_id
            WHERE metadata.analysis_run_id IS NULL
               OR metadata.metadata_version < ?
            ORDER BY results.analysis_run_id
            """,
            (CODE_ANALYSIS_ASSESSMENT_METADATA_VERSION,),
        )
        updated = 0
        while rows := cursor.fetchmany(25):
            for run_id, payload_json in rows:
                record = _decode_record_payload(payload_json, self.logger)
                if record is None:
                    continue
                self._upsert_assessment_metadata_locked(
                    connection,
                    str(run_id),
                    _build_record_assessment_metadata(record),
                )
                updated += 1
        if updated and self.logger:
            self.logger.info(
                "Backfilled code-analysis assessment metadata for %d result records",
                updated,
            )

    def _prune_locked(self, connection: sqlite3.Connection) -> None:
        retention_days = get_code_analysis_results_retention_days()
        if retention_days > 0:
            cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
            connection.execute(
                """
                DELETE FROM code_analysis_results
                WHERE record_timestamp != ''
                  AND record_timestamp < ?
                """,
                (cutoff,),
            )
        max_records = get_code_analysis_results_max_records()
        connection.execute(
            """
            DELETE FROM code_analysis_results
            WHERE analysis_run_id IN (
                SELECT analysis_run_id
                FROM code_analysis_results
                ORDER BY finished_at DESC, submitted_at DESC, analysis_run_id DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (max_records,),
        )
        connection.execute(
            """
            DELETE FROM code_analysis_result_applications
            WHERE analysis_run_id NOT IN (
                SELECT analysis_run_id FROM code_analysis_results
            )
            """
        )
        connection.execute(
            """
            DELETE FROM code_analysis_assessment_metadata
            WHERE analysis_run_id NOT IN (
                SELECT analysis_run_id FROM code_analysis_results
            )
            """
        )

    def record_queue_item_result(self, item: Any, result: dict[str, Any]) -> dict[str, Any]:
        record = build_code_analysis_result_record(item, result=result)
        run_id = _normalize_text(record.get("analysis_run_id"))
        if not run_id:
            raise ValueError("Cannot persist code-analysis result without an analysis run id")
        with self._lock:
            self._ensure_loaded()
            with closing(self._connect()) as connection:
                with connection:
                    self._upsert_record_locked(connection, record)
                    self._prune_locked(connection)
            self._invalidate_assessment_metadata_cache_locked()
        return record

    def get(self, run_id: str) -> Optional[dict[str, Any]]:
        normalized = _normalize_text(run_id)
        if not normalized:
            return None
        with self._lock:
            self._ensure_loaded()
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT payload_json
                    FROM code_analysis_results
                    WHERE analysis_run_id = ?
                    """,
                    (normalized,),
                ).fetchone()
        return _decode_record_payload(row[0], self.logger) if row else None

    def get_many(self, run_ids: list[str]) -> list[dict[str, Any]]:
        normalized_ids = list(
            dict.fromkeys(
                normalized
                for value in run_ids
                if (normalized := _normalize_text(value))
            )
        )
        if not normalized_ids:
            return []
        records: dict[str, dict[str, Any]] = {}
        with self._lock:
            self._ensure_loaded()
            with closing(self._connect()) as connection:
                for start in range(0, len(normalized_ids), 500):
                    batch = normalized_ids[start : start + 500]
                    rows = connection.execute(
                        f"""
                        SELECT analysis_run_id, payload_json
                        FROM code_analysis_results
                        WHERE analysis_run_id IN ({','.join('?' for _ in batch)})
                        """,
                        batch,
                    ).fetchall()
                    for run_id, payload_json in rows:
                        record = _decode_record_payload(payload_json, self.logger)
                        if record is not None:
                            records[str(run_id)] = record
        return [records[run_id] for run_id in normalized_ids if run_id in records]

    def delete(self, run_id: str) -> bool:
        normalized = _normalize_text(run_id)
        if not normalized:
            return False
        with self._lock:
            self._ensure_loaded()
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        DELETE FROM code_analysis_result_applications
                        WHERE analysis_run_id = ?
                        """,
                        (normalized,),
                    )
                    cursor = connection.execute(
                        """
                        DELETE FROM code_analysis_results
                        WHERE analysis_run_id = ?
                        """,
                        (normalized,),
                    )
                    self._prune_locked(connection)
                    deleted = cursor.rowcount > 0
            if deleted:
                self._invalidate_assessment_metadata_cache_locked()
            return deleted

    def record_application(
        self,
        *,
        analysis_run_id: str,
        finding_uuid: str,
        group_id: str,
        status: str,
        applied_by: str,
        workflow_id: str,
        payload_fingerprint: str = "",
    ) -> dict[str, Any]:
        run_id = _normalize_text(analysis_run_id)
        finding = _normalize_text(finding_uuid)
        normalized_status = _lower(status)
        if not run_id or not finding:
            raise ValueError("Analysis run id and finding uuid are required")
        if normalized_status not in {"applied", "queued", "failed"}:
            raise ValueError(f"Unsupported application status: {status}")
        application = {
            "analysis_run_id": run_id,
            "finding_uuid": finding,
            "group_id": _lower(group_id),
            "workflow_id": _normalize_text(workflow_id),
            "status": normalized_status,
            "applied_by": _normalize_text(applied_by),
            "applied_at": _utc_now_iso(),
            "payload_fingerprint": _normalize_text(payload_fingerprint),
        }
        with self._lock:
            self._ensure_loaded()
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO code_analysis_result_applications (
                            analysis_run_id,
                            finding_uuid,
                            group_id_lower,
                            workflow_id,
                            status,
                            applied_by,
                            applied_at,
                            payload_fingerprint
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (analysis_run_id, finding_uuid) DO UPDATE SET
                            group_id_lower = excluded.group_id_lower,
                            workflow_id = excluded.workflow_id,
                            status = CASE
                                WHEN code_analysis_result_applications.status = 'applied'
                                    THEN 'applied'
                                WHEN code_analysis_result_applications.status = 'queued'
                                     AND excluded.status = 'failed'
                                    THEN 'queued'
                                ELSE excluded.status
                            END,
                            applied_by = excluded.applied_by,
                            applied_at = excluded.applied_at,
                            payload_fingerprint = excluded.payload_fingerprint
                        """,
                        (
                            run_id,
                            finding,
                            _lower(group_id),
                            application["workflow_id"],
                            normalized_status,
                            application["applied_by"],
                            application["applied_at"],
                            application["payload_fingerprint"],
                        ),
                    )
        return application

    def list_applications(
        self,
        *,
        analysis_run_ids: Optional[list[str]] = None,
        group_id: Optional[str] = None,
        statuses: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        run_ids = list(dict.fromkeys(filter(None, map(_normalize_text, analysis_run_ids or []))))
        normalized_statuses = list(dict.fromkeys(filter(None, map(_lower, statuses or []))))
        where: list[str] = []
        params: list[Any] = []
        if analysis_run_ids is not None:
            if not run_ids:
                return []
            where.append(f"analysis_run_id IN ({','.join('?' for _ in run_ids)})")
            params.extend(run_ids)
        if group_id:
            where.append("group_id_lower = ?")
            params.append(_lower(group_id))
        if statuses is not None:
            if not normalized_statuses:
                return []
            where.append(f"status IN ({','.join('?' for _ in normalized_statuses)})")
            params.extend(normalized_statuses)
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        with self._lock:
            self._ensure_loaded()
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    f"""
                    SELECT analysis_run_id, finding_uuid, group_id_lower,
                           workflow_id, status, applied_by, applied_at,
                           payload_fingerprint
                    FROM code_analysis_result_applications
                    {where_sql}
                    ORDER BY applied_at DESC, analysis_run_id, finding_uuid
                    """,
                    params,
                ).fetchall()
        return [
            {
                "analysis_run_id": row[0],
                "finding_uuid": row[1],
                "group_id": row[2],
                "workflow_id": row[3],
                "status": row[4],
                "applied_by": row[5],
                "applied_at": row[6],
                "payload_fingerprint": row[7],
            }
            for row in rows
        ]

    def list(
        self,
        *,
        project_name: Optional[str] = None,
        vuln_id: Optional[str] = None,
        component_name: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
        include_result: bool = False,
    ) -> list[dict[str, Any]]:
        project_filter = _lower(project_name)
        vuln_filter = _lower(vuln_id)
        component_filter = _lower(component_name)
        source_filter = _lower(source)
        max_results = max(
            1,
            min(int(limit or 100), get_code_analysis_results_max_records()),
        )

        with self._lock:
            self._ensure_loaded()
            where = []
            params: list[Any] = []
            if project_filter and project_filter != "_all_":
                where.append("project_name_lower = ?")
                params.append(project_filter)
            if vuln_filter:
                where.append("vuln_id_lower = ?")
                params.append(vuln_filter)
            if component_filter:
                where.append("component_name_lower = ?")
                params.append(component_filter)
            if source_filter:
                where.append("source_lower = ?")
                params.append(source_filter)
            where_sql = f"WHERE {' AND '.join(where)}" if where else ""
            params.append(max_results)
            with closing(self._connect()) as connection:
                cursor = connection.execute(
                    f"""
                    SELECT payload_json
                    FROM code_analysis_results
                    {where_sql}
                    ORDER BY finished_at DESC, submitted_at DESC, analysis_run_id DESC
                    LIMIT ?
                    """,
                    params,
                )
                filtered: list[dict[str, Any]] = []
                while rows := cursor.fetchmany(100):
                    for row in rows:
                        payload = _decode_record_payload(row[0], self.logger)
                        if payload is None:
                            continue
                        if not include_result:
                            result = _as_dict(payload.get("result"))
                            if not _as_dict(payload.get("summary")) and result:
                                payload["summary"] = summarize_code_analysis_result(result)
                            payload.pop("result", None)
                            payload.pop("user_guidance", None)
                            payload.pop("follow_up_user_guidance", None)
                        filtered.append(payload)
        return filtered

    def list_result_metadata(
        self,
        *,
        project_name: Optional[str] = None,
        vuln_id: Optional[str] = None,
        component_name: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
        assessments_only: bool = False,
    ) -> list[dict[str, Any]]:
        project_filter = _lower(project_name)
        vuln_filter = _lower(vuln_id)
        component_filter = _lower(component_name)
        source_filter = _lower(source)
        max_results = max(
            1,
            min(int(limit or 100), get_code_analysis_results_max_records()),
        )
        with self._lock:
            self._ensure_loaded()
            where: list[str] = []
            params: list[Any] = []
            if vuln_filter:
                where.append(
                    """
                    (
                        metadata.vuln_id_lower = ?
                        OR (
                            metadata.vuln_id_lower = ''
                            AND results.vuln_id_lower = ?
                        )
                    )
                    """
                )
                params.extend([vuln_filter, vuln_filter])
            if assessments_only:
                where.append("metadata.has_assessment = 1")
            where_sql = f"WHERE {' AND '.join(where)}" if where else ""
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    f"""
                    SELECT
                        results.analysis_run_id,
                        results.project_name_lower,
                        results.vuln_id_lower,
                        results.component_name_lower,
                        results.source_lower,
                        results.context_fingerprint,
                        results.finished_at,
                        results.submitted_at,
                        results.recorded_at,
                        metadata.has_assessment,
                        metadata.vuln_id_lower,
                        metadata.project_names_json,
                        metadata.component_names_json,
                        metadata.scan_target_lower,
                        metadata.source_kind,
                        metadata.assessment_data_json,
                        metadata.record_data_json
                    FROM code_analysis_results AS results
                    JOIN code_analysis_assessment_metadata AS metadata
                      ON metadata.analysis_run_id = results.analysis_run_id
                    {where_sql}
                    ORDER BY results.finished_at DESC,
                             results.submitted_at DESC,
                             results.analysis_run_id DESC
                    """,
                    params,
                ).fetchall()

        records: list[dict[str, Any]] = []
        for row in rows:
            project_names = _decode_json_strings(row[11])
            component_names = _decode_json_strings(row[12])
            has_assessment = bool(row[9])
            normalized_vuln = _lower(row[10]) or _lower(row[2])
            scan_target = _lower(row[13]) or _lower(row[3])
            source_kind = _lower(row[14]) or "unknown"
            raw_source = _lower(row[4])
            if assessments_only and not has_assessment:
                continue
            if (
                project_filter
                and project_filter != "_all_"
                and project_filter not in project_names
                and project_filter != _lower(row[1])
            ):
                continue
            if vuln_filter and vuln_filter != normalized_vuln:
                continue
            if (
                component_filter
                and component_filter != scan_target
                and component_filter not in component_names
            ):
                continue
            if source_filter:
                source_aliases = {raw_source, source_kind}
                if source_kind == "auto":
                    source_aliases.add("automatic")
                if source_filter not in source_aliases:
                    continue
            assessment = _decode_json_dict(row[15])
            record_data = _decode_json_dict(row[16])
            records.append(
                {
                    **record_data,
                    "analysis_run_id": str(row[0]),
                    "project_name": (
                        _normalize_text(record_data.get("project_name"))
                        or (project_names[0] if project_names else "")
                        or _lower(row[1])
                    ),
                    "project_names": project_names,
                    "vuln_id": normalized_vuln,
                    "component_name": (
                        _normalize_text(record_data.get("component_name"))
                        or scan_target
                        or (component_names[0] if component_names else "")
                    ),
                    "component_names": component_names,
                    "scan_target": scan_target,
                    "source": (
                        _normalize_text(record_data.get("source"))
                        or raw_source
                        or source_kind
                    ),
                    "source_kind": source_kind,
                    "context_fingerprint": str(row[5] or ""),
                    "finished_at": str(row[6] or ""),
                    "submitted_at": str(row[7] or ""),
                    "recorded_at": str(row[8] or ""),
                    "status": "completed",
                    "has_assessment": has_assessment,
                    "assessment": assessment,
                    "summary": assessment,
                }
            )
            if len(records) >= max_results:
                break
        return records

    def list_assessment_metadata(
        self,
        *,
        project_name: Optional[str] = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._ensure_loaded()
            if self._assessment_metadata_cache is None:
                with closing(self._connect()) as connection:
                    stored_count = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM code_analysis_results"
                        ).fetchone()[0]
                    )
                    usable_count = int(
                        connection.execute(
                            """
                            SELECT COUNT(*)
                            FROM code_analysis_assessment_metadata
                            WHERE has_assessment = 1
                            """
                        ).fetchone()[0]
                    )
                records = self.list_result_metadata(
                    limit=get_code_analysis_results_max_records(),
                    assessments_only=True,
                )
                self._assessment_metadata_cache = {
                    "records": records,
                    "stored_analysis_results": stored_count,
                    "usable_assessment_results": usable_count,
                }
            cached = self._assessment_metadata_cache

            normalized_project = _lower(project_name)
            records = list(cached["records"])
            if normalized_project and normalized_project != "_all_":
                records = [
                    record
                    for record in records
                    if normalized_project
                    in {
                        *map(_lower, record.get("project_names") or []),
                        _lower(record.get("project_name")),
                    }
                ]
        return {
            "records": records,
            "stored_analysis_results": cached["stored_analysis_results"],
            "usable_assessment_results": cached["usable_assessment_results"],
        }

    def find_latest(
        self,
        *,
        project_name: Optional[str] = None,
        vuln_id: Optional[str] = None,
        component_name: Optional[str] = None,
        source: Optional[str] = None,
        context_fingerprint: Optional[str] = None,
        freshness_days: Optional[int] = None,
        include_result: bool = False,
    ) -> Optional[dict[str, Any]]:
        freshness = (
            get_code_analysis_result_freshness_days()
            if freshness_days is None
            else max(0, int(freshness_days))
        )
        records = self.list(
            project_name=project_name,
            vuln_id=vuln_id,
            component_name=component_name,
            source=source,
            limit=500,
            include_result=include_result,
        )
        normalized_fingerprint = _normalize_text(context_fingerprint)
        for record in records:
            if normalized_fingerprint and _normalize_text(record.get("context_fingerprint")) != normalized_fingerprint:
                continue
            if not _record_within_freshness(record, freshness):
                continue
            return record
        return None

    def compact_context(self, run_id: str) -> Optional[dict[str, Any]]:
        record = self.get(run_id)
        if not record:
            return None
        compact_context = record.get("compact_context")
        if isinstance(compact_context, dict):
            return compact_context
        return build_compact_analysis_context(record)

    def status(self) -> dict[str, Any]:
        with self._lock:
            self._ensure_loaded()
            with closing(self._connect()) as connection:
                count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM code_analysis_results"
                    ).fetchone()[0]
                )
        return {
            "schema_version": CODE_ANALYSIS_RESULT_SCHEMA_VERSION,
            "storage": "sqlite",
            "path": self._path(),
            "legacy_json_path": self._legacy_json_path(),
            "record_count": count,
            "max_records": get_code_analysis_results_max_records(),
            "retention_days": get_code_analysis_results_retention_days(),
            "freshness_days": get_code_analysis_result_freshness_days(),
            "store_guidance": get_code_analysis_results_store_guidance(),
        }
