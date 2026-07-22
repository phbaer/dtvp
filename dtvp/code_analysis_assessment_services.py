from __future__ import annotations

from typing import Any


NON_FINAL_ASSESSMENT_STATUSES = {
    "queued",
    "running",
    "pending",
    "failed",
    "error",
    "cancelled",
    "canceled",
    "aborted",
}
ASSESSMENT_METADATA_VERSION = 1


def text(value: Any) -> str:
    return str(value or "").strip()


def lower(value: Any) -> str:
    return text(value).lower()


def mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def record_run_id(record: dict[str, Any]) -> str:
    return text(
        record.get("analysis_run_id")
        or record.get("run_id")
        or record.get("queue_id")
    )


def record_target(record: dict[str, Any]) -> dict[str, Any]:
    return mapping(mapping(record.get("compact_context")).get("target"))


def record_context_summary(record: dict[str, Any]) -> dict[str, Any]:
    direct = mapping(record.get("context_summary"))
    request_context = mapping(
        mapping(record.get("compact_context")).get("request_context")
    )
    compact = mapping(request_context.get("context_summary"))
    meaningful_direct = {
        key: value
        for key, value in direct.items()
        if value not in (None, "", [], {})
    }
    return {**compact, **meaningful_direct}


def record_vulnerability_id(record: dict[str, Any]) -> str:
    context_summary = record_context_summary(record)
    return lower(
        record.get("vuln_id")
        or context_summary.get("vuln_id")
        or record_target(record).get("vuln_id")
    )


def record_result(record: dict[str, Any]) -> dict[str, Any]:
    for value in (
        record.get("result"),
        record.get("response"),
        record.get("output"),
    ):
        container = mapping(value)
        nested = mapping(container.get("result"))
        if nested and not mapping(container.get("assessment")):
            container = nested
        if container:
            return container
    return {}


def _summary_assessment(record: dict[str, Any]) -> dict[str, Any]:
    summary = mapping(record.get("summary"))
    assessment_keys = {
        "affected",
        "verdict",
        "confidence",
        "exposure",
        "analysis",
        "justification",
        "response",
        "summary",
        "reasoning",
        "details",
    }
    if not any(summary.get(key) not in (None, "", [], {}) for key in assessment_keys):
        return {}
    assessment = {
        key: value
        for key, value in summary.items()
        if key
        not in {
            "versions_checked",
            "component_results",
            "step_count",
            "original_cvss_score",
            "original_cvss_vector",
            "adjusted_cvss_score",
            "adjusted_cvss_vector",
            "cvss_summary",
            "cvss_reasons",
        }
    }
    adjusted_values = {
        "original_score": summary.get("original_cvss_score"),
        "original_vector": summary.get("original_cvss_vector"),
        "adjusted_score": summary.get("adjusted_cvss_score"),
        "adjusted_vector": summary.get("adjusted_cvss_vector"),
        "summary": summary.get("cvss_summary"),
        "reasons": summary.get("cvss_reasons"),
    }
    adjusted_cvss = {
        key: value
        for key, value in adjusted_values.items()
        if value not in (None, "", [], {})
    }
    if adjusted_cvss:
        assessment["adjusted_cvss"] = adjusted_cvss
    return assessment


def record_assessment(record: dict[str, Any]) -> dict[str, Any] | None:
    result = record_result(record)
    direct = mapping(result.get("assessment"))
    if not direct and any(
        result.get(key) not in (None, "", [], {})
        for key in ("verdict", "affected", "analysis", "summary", "reasoning")
    ):
        direct = result
    if not direct:
        direct = mapping(record.get("assessment"))
    assessment = {**_summary_assessment(record), **direct}
    return assessment or None


def record_project_names(record: dict[str, Any]) -> set[str]:
    context_summary = record_context_summary(record)
    values = [
        record.get("project_name"),
        context_summary.get("project_name"),
        record_target(record).get("project_name"),
    ]
    values.extend(record.get("project_names") or [])
    values.extend(
        component.get("project_name")
        for component in (context_summary.get("components") or [])
        if isinstance(component, dict)
    )
    return {name for value in values if (name := lower(value))}


def record_component_names(record: dict[str, Any]) -> set[str]:
    context_summary = record_context_summary(record)
    result = record_result(record)
    summary = mapping(record.get("summary"))
    values = [
        record.get("component_name"),
        context_summary.get("target_component"),
        record_target(record).get("component_name"),
    ]
    values.extend(record.get("component_names") or [])
    values.extend(
        component.get("component_name")
        for component in (context_summary.get("components") or [])
        if isinstance(component, dict)
    )
    values.extend(
        component.get("component")
        for component in (
            result.get("component_results")
            or summary.get("component_results")
            or []
        )
        if isinstance(component, dict)
    )
    return {name for value in values if (name := lower(value))}


def record_scan_target(record: dict[str, Any]) -> str:
    context_summary = record_context_summary(record)
    return lower(
        record.get("scan_target")
        or record.get("component_name")
        or context_summary.get("target_component")
        or record_target(record).get("component_name")
    )


def record_source(record: dict[str, Any]) -> str:
    context_source = mapping(
        mapping(record.get("compact_context")).get("request_context")
    ).get("source")
    return lower(record.get("source") or context_source)


def discover_assessment_records(
    result_store: Any,
    diagnostics: dict[str, int] | None = None,
    *,
    include_result: bool = True,
) -> list[dict[str, Any]]:
    if result_store is None:
        if diagnostics is not None:
            diagnostics.update(
                stored_analysis_results=0,
                usable_assessment_results=0,
            )
        return []
    records = result_store.list(
        limit=1_000_000,
        include_result=include_result,
    )
    latest: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        if "benchmark" in record_source(record):
            continue
        if lower(record.get("status")) in NON_FINAL_ASSESSMENT_STATUSES:
            continue
        if not record_run_id(record) or record_assessment(record) is None:
            continue
        projects = sorted(record_project_names(record))
        key = (
            record_vulnerability_id(record),
            projects[0] if projects else "",
            record_scan_target(record),
        )
        latest.setdefault(key, record)
    if diagnostics is not None:
        diagnostics.update(
            stored_analysis_results=len(records),
            usable_assessment_results=len(latest),
        )
    return list(latest.values())


def discover_assessment_metadata(
    result_store: Any,
    diagnostics: dict[str, int] | None = None,
    *,
    project_name: str | None = None,
) -> list[dict[str, Any]]:
    if result_store is not None and hasattr(result_store, "list_assessment_metadata"):
        result = result_store.list_assessment_metadata(project_name=project_name)
        latest: dict[tuple[str, str, str], dict[str, Any]] = {}
        for record in result.get("records") or []:
            if not isinstance(record, dict) or not record.get("has_assessment"):
                continue
            projects = sorted(record_project_names(record))
            key = (
                record_vulnerability_id(record),
                projects[0] if projects else "",
                record_scan_target(record),
            )
            latest.setdefault(key, record)
        if diagnostics is not None:
            diagnostics.update(
                stored_analysis_results=int(
                    result.get("stored_analysis_results") or 0
                ),
                usable_assessment_results=len(latest),
            )
        return list(latest.values())

    records = discover_assessment_records(
        result_store,
        diagnostics,
        include_result=False,
    )
    normalized_project = lower(project_name)
    if not normalized_project or normalized_project == "_all_":
        return records
    return [
        record
        for record in records
        if not record_project_names(record)
        or normalized_project in record_project_names(record)
    ]


def group_vulnerability_ids(group: dict[str, Any]) -> set[str]:
    return {
        normalized
        for value in [group.get("id"), *(group.get("aliases") or [])]
        if (normalized := lower(value))
    }


def group_project_names(group: dict[str, Any]) -> set[str]:
    return {
        name
        for version in (group.get("affected_versions") or [])
        for component in (version.get("components") or [])
        if isinstance(component, dict)
        if (name := lower(component.get("project_name") or version.get("project_name")))
    }


def group_component_names(group: dict[str, Any]) -> set[str]:
    return {
        name
        for version in (group.get("affected_versions") or [])
        for component in (version.get("components") or [])
        if isinstance(component, dict)
        if (name := lower(component.get("component_name")))
    }


def records_for_group(
    group: dict[str, Any],
    records: list[dict[str, Any]],
    record_index: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    vulnerability_ids = group_vulnerability_ids(group)
    project_names = group_project_names(group)
    if record_index is not None:
        candidates = [
            record
            for vulnerability_id in vulnerability_ids
            for record in record_index["by_vulnerability_id"].get(
                vulnerability_id,
                (),
            )
        ]
    else:
        candidates = records
    matched: list[dict[str, Any]] = []
    seen_run_ids: set[str] = set()
    for record in candidates:
        if record_vulnerability_id(record) not in vulnerability_ids:
            continue
        projects = record_project_names(record)
        if project_names and projects and project_names.isdisjoint(projects):
            continue
        run_id = record_run_id(record)
        if run_id and run_id in seen_run_ids:
            continue
        if run_id:
            seen_run_ids.add(run_id)
        matched.append(record)
    return matched


def build_assessment_match_index(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    records_by_run_id = {
        run_id: record
        for record in records
        if (run_id := record_run_id(record))
    }
    by_vulnerability_id: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        vulnerability_id = record_vulnerability_id(record)
        if vulnerability_id:
            by_vulnerability_id.setdefault(vulnerability_id, []).append(record)
    return {
        "by_vulnerability_id": by_vulnerability_id,
        "records_by_run_id": records_by_run_id,
    }


def record_source_kind(
    record: dict[str, Any],
    records_by_run_id: dict[str, dict[str, Any]] | None = None,
) -> str:
    stored_kind = lower(record.get("source_kind"))
    if stored_kind in {"auto", "manual", "unknown"}:
        return stored_kind
    source = record_source(record)
    if source in {"automatic", "auto", "scheduled"}:
        return "auto"
    if source in {"manual", "reviewer", "interactive"}:
        return "manual"
    if source in {"follow-up", "followup"}:
        parent_id = text(record.get("parent_run_id"))
        parent = (records_by_run_id or {}).get(parent_id)
        return record_source_kind(parent, records_by_run_id) if parent else "manual"
    return "unknown"


def build_record_assessment_metadata(record: dict[str, Any]) -> dict[str, Any]:
    assessment = record_assessment(record)
    usable = bool(
        record_run_id(record)
        and assessment is not None
        and "benchmark" not in record_source(record)
        and lower(record.get("status")) not in NON_FINAL_ASSESSMENT_STATUSES
    )
    assessment_data = {
        key: assessment.get(key)
        for key in (
            "affected",
            "verdict",
            "analysis",
            "confidence",
            "exposure",
        )
        if assessment is not None
        and assessment.get(key) not in (None, "", [], {})
    }
    context_summary = record_context_summary(record)
    record_data = {
        key: record.get(key)
        for key in (
            "schema_version",
            "queue_id",
            "job_id",
            "parent_run_id",
            "parent_job_id",
            "project_name",
            "vuln_id",
            "component_name",
            "source",
            "submitted_by",
            "submitted_at",
            "started_at",
            "finished_at",
            "recorded_at",
            "status",
            "model",
            "llm_backend",
            "llm_provider",
            "cvss_vector",
            "context_fingerprint",
        )
        if record.get(key) not in (None, "", [], {})
    }
    compact_context_summary = {
        key: context_summary.get(key)
        for key in ("project_versions", "instance_count")
        if context_summary.get(key) not in (None, "", [], {})
    }
    if compact_context_summary:
        record_data["context_summary"] = compact_context_summary
    return {
        "metadata_version": ASSESSMENT_METADATA_VERSION,
        "has_assessment": usable,
        "vuln_id": record_vulnerability_id(record),
        "project_names": sorted(record_project_names(record)),
        "component_names": sorted(record_component_names(record)),
        "scan_target": record_scan_target(record),
        "source_kind": record_source_kind(record),
        "assessment": assessment_data if usable else {},
        "record": record_data,
    }


def assessment_status_for_group(
    group: dict[str, Any],
    records: list[dict[str, Any]],
    record_index: dict[str, Any] | None = None,
) -> str | None:
    effective_index = record_index or build_assessment_match_index(records)
    matched = records_for_group(group, records, effective_index)
    if not matched:
        return None
    records_by_run_id = effective_index["records_by_run_id"]
    source_kinds = {
        record_source_kind(record, records_by_run_id) for record in matched
    }
    covered_components = {
        component
        for record in matched
        for component in record_component_names(record)
    }
    expected_components = group_component_names(group)
    if expected_components and not expected_components.issubset(covered_components):
        return "partial"
    # Older reviewer-triggered analyses do not always carry a source marker.
    # Complete coverage is still useful, so reserve "partial" exclusively for
    # missing component coverage and classify unmarked records as manual here.
    known_kinds = {
        "manual" if source_kind == "unknown" else source_kind
        for source_kind in source_kinds
    } & {"auto", "manual"}
    if known_kinds == {"auto", "manual"}:
        return "mixed"
    if known_kinds == {"auto"}:
        return "auto"
    if known_kinds == {"manual"}:
        return "manual"
    return "partial"


def build_assessment_index(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records_by_run_id = {
        run_id: record
        for record in records
        if (run_id := record_run_id(record))
    }
    return [
        {
            "analysis_run_id": record_run_id(record),
            "vuln_id": record_vulnerability_id(record),
            "project_names": sorted(record_project_names(record)),
            "component_names": sorted(record_component_names(record)),
            "source_kind": record_source_kind(record, records_by_run_id),
        }
        for record in records
        if record_vulnerability_id(record)
    ]
