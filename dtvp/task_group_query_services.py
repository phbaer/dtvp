import base64
import json
from datetime import datetime
from typing import Any

from .inconsistency import INCONSISTENCY_REASONS


DAY_MS = 24 * 60 * 60 * 1000
TASK_GROUP_QUERY_INDEX_VERSION = 6
TASK_GROUP_QUERY_CACHE_LIMIT = 64
TASK_GROUP_CURSOR_VERSION = 1
ANALYSIS_STATE_ORDER = {
    "EXPLOITABLE": 0,
    "IN_TRIAGE": 1,
    "NOT_SET": 2,
    "RESOLVED": 3,
    "FALSE_POSITIVE": 4,
    "NOT_AFFECTED": 5,
}


def encode_task_group_cursor(offset: int) -> str | None:
    if offset <= 0:
        return None
    payload = {"v": TASK_GROUP_CURSOR_VERSION, "o": int(offset)}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_task_group_cursor(cursor: str) -> int:
    token = str(cursor or "").strip()
    if not token:
        return 0
    try:
        padded = token + "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        if payload.get("v") != TASK_GROUP_CURSOR_VERSION:
            raise ValueError
        offset = int(payload.get("o", 0))
        if offset < 0:
            raise ValueError
    except Exception as exc:
        raise ValueError("Invalid task group cursor") from exc
    return offset


def split_query_values(values: list[str] | None) -> list[str]:
    if not values:
        return []

    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        for part in str(value or "").split(","):
            text = part.strip()
            if not text or text in seen:
                continue
            result.append(text)
            seen.add(text)
    return result


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        result.append(text)
        seen.add(text)
    return result


def _components_for_group(group: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        component
        for affected_version in group.get("affected_versions") or []
        for component in affected_version.get("components", []) or []
    ]


def _component_names_for_group(group: dict[str, Any]) -> list[str]:
    metadata = group.get("list_metadata") or {}
    metadata_names = _string_list(metadata.get("component_names"))
    if metadata_names:
        return metadata_names
    return _string_list(
        [component.get("component_name") for component in _components_for_group(group)]
    )


def _versions_for_group(group: dict[str, Any]) -> list[str]:
    metadata = group.get("list_metadata") or {}
    metadata_versions = _string_list(metadata.get("versions"))
    if metadata_versions:
        return metadata_versions
    return _string_list(
        [
            affected_version.get("project_version") or affected_version.get("version")
            for affected_version in group.get("affected_versions") or []
        ]
    )


def _attributed_on_ms_values(group: dict[str, Any]) -> list[int]:
    metadata = group.get("list_metadata") or {}
    values = metadata.get("attributed_on_ms_values")
    if isinstance(values, list):
        result: list[int] = []
        seen: set[int] = set()
        for value in values:
            try:
                number = int(value)
            except (TypeError, ValueError):
                continue
            if number in seen:
                continue
            result.append(number)
            seen.add(number)
        return result
    return []


def _dependency_relationship_for_group(group: dict[str, Any]) -> str:
    metadata = group.get("list_metadata") or {}
    relationship = str(metadata.get("dependency_relationship") or "").upper()
    if relationship in {"DIRECT", "TRANSITIVE", "UNKNOWN"}:
        return relationship

    direct_flags = [
        component.get("is_direct_dependency")
        for component in _components_for_group(group)
        if isinstance(component.get("is_direct_dependency"), bool)
    ]
    if True in direct_flags:
        return "DIRECT"
    if False in direct_flags:
        return "TRANSITIVE"
    return "UNKNOWN"


def _score_severity_rank(score: Any) -> int:
    try:
        value = float(score)
    except (TypeError, ValueError):
        value = 0.0
    if value >= 9.0:
        return 0
    if value >= 7.0:
        return 1
    if value >= 4.0:
        return 2
    if value >= 0.1:
        return 3
    return 4


def _score_value(score: Any) -> float:
    try:
        return float(score)
    except (TypeError, ValueError):
        return 0.0


def _group_list_fields(group: dict[str, Any]) -> dict[str, Any]:
    metadata = group.get("list_metadata") or {}
    tags = _string_list(group.get("tags") or [])
    aliases = _string_list(group.get("aliases") or [])
    aliases_lower = [_lower(value) for value in aliases]
    assignees = _string_list(group.get("assignees") or [])
    component_names = _component_names_for_group(group)
    versions = _versions_for_group(group)
    versions_lower = [_lower(value) for value in versions]
    id_lower = _lower(group.get("id"))
    base_score = group.get("cvss_score")
    if base_score is None:
        base_score = group.get("cvss", 0)
    rescored_score = group.get("rescored_cvss")
    if rescored_score is None:
        rescored_score = base_score
    assessment_restore_count = int(
        metadata.get("assessment_restore_count")
        or group.get("assessment_restore_count")
        or 0
    )
    assessment_restore_recoverable_count = int(
        metadata.get("assessment_restore_recoverable_count")
        or group.get("assessment_restore_recoverable_count")
        or 0
    )
    assessment_restore_status = str(
        metadata.get("assessment_restore_status")
        or group.get("assessment_restore_status")
        or ""
    )
    inconsistency_reasons = _string_list(metadata.get("inconsistency_reasons"))

    searchable_text = " ".join(
        value
        for value in [
            _lower(group.get("id")),
            _lower(group.get("title")),
            _lower(group.get("description")),
            *[_lower(value) for value in aliases],
            *[_lower(value) for value in tags],
            *[_lower(value) for value in assignees],
            *[_lower(value) for value in component_names],
            *[_lower(value) for value in versions],
            _lower(metadata.get("lifecycle")),
            _lower(metadata.get("technical_state")),
            _lower(_dependency_relationship_for_group(group)),
            _lower(assessment_restore_status),
            *[_lower(value) for value in inconsistency_reasons],
        ]
        if value
    )

    return {
        "id": str(group.get("id") or ""),
        "id_lower": id_lower,
        "aliases": aliases,
        "aliases_lower": aliases_lower,
        "candidate_ids_lower": {
            value for value in [id_lower, *aliases_lower] if value
        },
        "tags": tags,
        "tags_lower": [_lower(value) for value in tags],
        "first_tag": tags[0] if tags else "",
        "component_names": component_names,
        "component_names_lower": [_lower(value) for value in component_names],
        "assignees": assignees,
        "assignees_lower": [_lower(value) for value in assignees],
        "versions": versions,
        "versions_lower": versions_lower,
        "versions_lower_set": set(versions_lower),
        "searchable_text": searchable_text,
        "lifecycle": str(metadata.get("lifecycle") or "OPEN"),
        "inconsistency_reasons": inconsistency_reasons,
        "inconsistency_reason_set": {
            value.upper() for value in inconsistency_reasons
        },
        "is_open": bool(metadata.get("is_open")),
        "is_pending": bool(metadata.get("is_pending")),
        "technical_state": str(metadata.get("technical_state") or "NOT_SET"),
        "dependency_relationship": _dependency_relationship_for_group(group),
        "cvss_version_mismatch": bool(metadata.get("cvss_version_mismatch")),
        "attributed_on_ms_values": _attributed_on_ms_values(group),
        "base_score": _score_value(base_score),
        "rescored_score": _score_value(rescored_score),
        "base_severity_rank": _score_severity_rank(base_score),
        "rescored_severity_rank": _score_severity_rank(rescored_score),
        "assessment_restore_count": assessment_restore_count,
        "assessment_restore_recoverable_count": assessment_restore_recoverable_count,
        "assessment_restore_status": assessment_restore_status,
    }


def _matches_lifecycle(fields: dict[str, Any], filters: set[str]) -> bool:
    if not filters:
        return True
    lifecycle = fields["lifecycle"]
    return (
        ("OPEN" in filters and fields["is_open"])
        or ("ASSESSED" in filters and lifecycle == "ASSESSED")
        or ("ASSESSED_LEGACY" in filters and lifecycle == "ASSESSED_LEGACY")
        or ("INCOMPLETE" in filters and lifecycle == "INCOMPLETE")
        or ("INCONSISTENT" in filters and lifecycle == "INCONSISTENT")
        or ("NEEDS_APPROVAL" in filters and fields["is_pending"])
    )


def _matches_inconsistency_reason(
    fields: dict[str, Any],
    filters: set[str],
) -> bool:
    if not filters:
        return True
    return not fields["inconsistency_reason_set"].isdisjoint(filters)


def _matches_attribution_age(
    fields: dict[str, Any],
    days: int | None,
    mode: str,
    now_ms: int,
) -> bool:
    if days is None:
        return True
    cutoff = now_ms - days * DAY_MS
    values = fields["attributed_on_ms_values"]
    if mode == "younger":
        return any(value >= cutoff for value in values)
    return any(value < cutoff for value in values)


def _matches_all_terms(values: list[str], terms: tuple[str, ...]) -> bool:
    if not terms:
        return True
    return all(any(term in value for value in values) for term in terms)


def _matches_versions(values: set[str], filters: set[str]) -> bool:
    if not filters:
        return True
    return not values.isdisjoint(filters)


def _matches_tmrescore_proposal(
    fields: dict[str, Any],
    filters: set[str],
    proposal_id_set: set[str],
) -> bool:
    if not filters:
        return True

    if {"WITH_PROPOSAL", "WITHOUT_PROPOSAL"}.issubset(filters):
        return True

    has_proposal = not fields["candidate_ids_lower"].isdisjoint(proposal_id_set)

    return (
        ("WITH_PROPOSAL" in filters and has_proposal)
        or ("WITHOUT_PROPOSAL" in filters and not has_proposal)
    )


def _matches_automatic_assessment(
    fields: dict[str, Any],
    filters: set[str],
    automatic_assessment_id_set: set[str],
) -> bool:
    if not filters:
        return True

    if {"WITH_AUTOMATIC_ASSESSMENT", "WITHOUT_AUTOMATIC_ASSESSMENT"}.issubset(filters):
        return True

    has_automatic_assessment = not fields["candidate_ids_lower"].isdisjoint(
        automatic_assessment_id_set
    )

    return (
        "WITH_AUTOMATIC_ASSESSMENT" in filters
        and has_automatic_assessment
    ) or (
        "WITHOUT_AUTOMATIC_ASSESSMENT" in filters
        and not has_automatic_assessment
    )


def _matches_task_group_fields(
    fields: dict[str, Any],
    *,
    q_terms: tuple[str, ...],
    lifecycle: set[str],
    inconsistency_reason: set[str],
    analysis: set[str],
    tag_terms: tuple[str, ...],
    vuln_id_terms: tuple[str, ...],
    component_terms: tuple[str, ...],
    assignee_terms: tuple[str, ...],
    dependency: set[str],
    versions: set[str],
    cvss_mismatch: bool,
    attributed_before_days: int | None,
    attribution_mode: str,
    tmrescore: set[str],
    tmrescore_proposal_id_set: set[str],
    automatic_assessment: set[str],
    automatic_assessment_id_set: set[str],
    now_ms: int,
) -> bool:
    if q_terms and not all(term in fields["searchable_text"] for term in q_terms):
        return False
    if not _matches_lifecycle(fields, lifecycle):
        return False
    if not _matches_inconsistency_reason(fields, inconsistency_reason):
        return False
    if analysis and fields["technical_state"] not in analysis:
        return False
    if tag_terms and not _matches_all_terms(fields["tags_lower"], tag_terms):
        return False
    if vuln_id_terms and not _matches_all_terms(
        [fields["id_lower"], *fields["aliases_lower"]],
        vuln_id_terms,
    ):
        return False
    if component_terms and not _matches_all_terms(
        fields["component_names_lower"], component_terms
    ):
        return False
    if assignee_terms and not _matches_all_terms(
        fields["assignees_lower"], assignee_terms
    ):
        return False
    if dependency and fields["dependency_relationship"] not in dependency:
        return False
    if not _matches_versions(fields["versions_lower_set"], versions):
        return False
    if cvss_mismatch and not fields["cvss_version_mismatch"]:
        return False
    if not _matches_attribution_age(
        fields,
        attributed_before_days,
        attribution_mode,
        now_ms,
    ):
        return False
    if not _matches_tmrescore_proposal(fields, tmrescore, tmrescore_proposal_id_set):
        return False
    if not _matches_automatic_assessment(
        fields,
        automatic_assessment,
        automatic_assessment_id_set,
    ):
        return False
    return True


def _task_group_sort_key(row: dict[str, Any], sort_by: str) -> tuple[Any, str]:
    fields = row["fields"]
    if sort_by == "analysis":
        primary: Any = ANALYSIS_STATE_ORDER.get(fields["technical_state"], 99)
    elif sort_by == "tags":
        primary = fields["first_tag"]
    elif sort_by == "severity":
        primary = -fields["base_severity_rank"]
    elif sort_by == "rescored-severity":
        primary = -fields["rescored_severity_rank"]
    elif sort_by == "score":
        primary = fields["base_score"]
    elif sort_by == "rescored":
        primary = fields["rescored_score"]
    elif sort_by == "id":
        primary = fields["id"]
    else:
        primary = ""
    return primary, fields["id"]


def _empty_lifecycle_counts() -> dict[str, int]:
    return {
        "OPEN": 0,
        "ASSESSED": 0,
        "ASSESSED_LEGACY": 0,
        "INCOMPLETE": 0,
        "INCONSISTENT": 0,
        "NEEDS_APPROVAL": 0,
    }


def _empty_analysis_counts() -> dict[str, int]:
    return {
        "EXPLOITABLE": 0,
        "IN_TRIAGE": 0,
        "NOT_SET": 0,
        "RESOLVED": 0,
        "FALSE_POSITIVE": 0,
        "NOT_AFFECTED": 0,
    }


def _empty_dependency_counts() -> dict[str, int]:
    return {"direct": 0, "transitive": 0, "unknown": 0}


def _empty_tmrescore_counts() -> dict[str, int]:
    return {"WITH_PROPOSAL": 0, "WITHOUT_PROPOSAL": 0}


def _empty_automatic_assessment_counts() -> dict[str, int]:
    return {
        "WITH_AUTOMATIC_ASSESSMENT": 0,
        "WITHOUT_AUTOMATIC_ASSESSMENT": 0,
    }


def _empty_assessment_restore_counts() -> dict[str, int]:
    return {
        "WITH_RESTORE": 0,
        "RECOVERABLE": 0,
        "AMBIGUOUS": 0,
        "NO_HISTORY": 0,
    }


def _empty_inconsistency_reason_counts() -> dict[str, int]:
    return {reason: 0 for reason in INCONSISTENCY_REASONS}


def _increment(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def _normalized_upper_tuple(values: list[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            str(value or "").strip().upper()
            for value in values
            if str(value or "").strip()
        )
    )


def _normalized_lower_tuple(values: list[str]) -> tuple[str, ...]:
    return tuple(sorted(_lower(value) for value in values if _lower(value)))


def _normalized_upper_set(values: list[str]) -> set[str]:
    return {
        str(value or "").strip().upper()
        for value in values
        if str(value or "").strip()
    }


def _normalized_lower_set(values: list[str]) -> set[str]:
    return {_lower(value) for value in values if _lower(value)}


def _build_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    lifecycle_counts = _empty_lifecycle_counts()
    analysis_counts = _empty_analysis_counts()
    dependency_counts = _empty_dependency_counts()
    ids: dict[str, int] = {}
    versions: dict[str, int] = {}
    tags: dict[str, int] = {}
    assignees: dict[str, int] = {}
    components: dict[str, int] = {}
    team_tags: dict[str, dict[str, int]] = {}
    cvss_version_mismatch = 0
    assessment_restore_counts = _empty_assessment_restore_counts()
    inconsistency_reason_counts = _empty_inconsistency_reason_counts()

    for row in rows:
        fields = row["fields"]
        if fields["is_open"]:
            lifecycle_counts["OPEN"] += 1
        if fields["lifecycle"] in lifecycle_counts and fields["lifecycle"] not in {
            "OPEN",
            "NEEDS_APPROVAL",
        }:
            lifecycle_counts[fields["lifecycle"]] += 1
        if fields["is_pending"]:
            lifecycle_counts["NEEDS_APPROVAL"] += 1

        _increment(analysis_counts, fields["technical_state"])
        relationship_key = fields["dependency_relationship"].lower()
        if relationship_key in dependency_counts:
            dependency_counts[relationship_key] += 1
        if fields["cvss_version_mismatch"]:
            cvss_version_mismatch += 1
        if fields["assessment_restore_count"] > 0:
            assessment_restore_counts["WITH_RESTORE"] += 1
            status = str(fields.get("assessment_restore_status") or "").upper()
            if status == "RECOVERABLE":
                assessment_restore_counts["RECOVERABLE"] += 1
            elif status == "AMBIGUOUS":
                assessment_restore_counts["AMBIGUOUS"] += 1
            elif status == "NO_HISTORY":
                assessment_restore_counts["NO_HISTORY"] += 1
        for reason in fields["inconsistency_reasons"]:
            _increment(inconsistency_reason_counts, reason)

        seen_ids = set()
        for identifier in [fields["id"], *fields["aliases"]]:
            key = str(identifier or "").strip()
            normalized = _lower(key)
            if not key or normalized in seen_ids:
                continue
            seen_ids.add(normalized)
            _increment(ids, key)
        for version in fields["versions"]:
            _increment(versions, version)
        for tag in fields["tags"]:
            _increment(tags, tag)
            if tag not in team_tags:
                team_tags[tag] = {"open": 0, "assessed": 0}
            if fields["is_open"]:
                team_tags[tag]["open"] += 1
            else:
                team_tags[tag]["assessed"] += 1
        for assignee in fields["assignees"]:
            _increment(assignees, assignee)
        for component in fields["component_names"]:
            _increment(components, component)

    return {
        "total": len(rows),
        "lifecycle": lifecycle_counts,
        "analysis": analysis_counts,
        "dependency_relationship": dependency_counts,
        "cvss_version_mismatch": cvss_version_mismatch,
        "ids": ids,
        "versions": versions,
        "tags": tags,
        "assignees": assignees,
        "components": components,
        "team_tags": team_tags,
        "assessment_restore": assessment_restore_counts,
        "inconsistency_reason": inconsistency_reason_counts,
    }


def _copy_counts(counts: dict[str, Any]) -> dict[str, Any]:
    return {
        **counts,
        "lifecycle": dict(counts.get("lifecycle", {})),
        "inconsistency_reason": dict(counts.get("inconsistency_reason", {})),
        "analysis": dict(counts.get("analysis", {})),
        "dependency_relationship": dict(counts.get("dependency_relationship", {})),
        "ids": dict(counts.get("ids", {})),
        "versions": dict(counts.get("versions", {})),
        "tags": dict(counts.get("tags", {})),
        "assignees": dict(counts.get("assignees", {})),
        "components": dict(counts.get("components", {})),
        "team_tags": {
            team: dict(values)
            for team, values in (counts.get("team_tags") or {}).items()
            if isinstance(values, dict)
        },
        "assessment_restore": dict(counts.get("assessment_restore", {})),
    }


def _has_tmrescore_proposal(
    fields: dict[str, Any],
    proposal_id_set: set[str],
) -> bool:
    if not proposal_id_set:
        return False
    return not fields["candidate_ids_lower"].isdisjoint(proposal_id_set)


def _has_automatic_assessment(
    fields: dict[str, Any],
    automatic_assessment_id_set: set[str],
) -> bool:
    if not automatic_assessment_id_set:
        return False
    return not fields["candidate_ids_lower"].isdisjoint(automatic_assessment_id_set)


def _add_dynamic_counts(
    counts: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    tmrescore_proposal_id_set: set[str],
    automatic_assessment_id_set: set[str],
    attributed_before_days: int | None,
    attribution_mode: str,
    now_ms: int,
) -> dict[str, Any]:
    result = _copy_counts(counts)
    tmrescore_counts = _empty_tmrescore_counts()
    automatic_assessment_counts = _empty_automatic_assessment_counts()
    attribution_age_count = 0

    if (
        not tmrescore_proposal_id_set
        and not automatic_assessment_id_set
        and attributed_before_days is None
    ):
        tmrescore_counts["WITHOUT_PROPOSAL"] = len(rows)
        automatic_assessment_counts["WITHOUT_AUTOMATIC_ASSESSMENT"] = len(rows)
        result["tmrescore"] = tmrescore_counts
        result["automatic_assessment"] = automatic_assessment_counts
        result["attribution_age"] = attribution_age_count
        return result

    for row in rows:
        fields = row["fields"]
        if _has_tmrescore_proposal(fields, tmrescore_proposal_id_set):
            tmrescore_counts["WITH_PROPOSAL"] += 1
        else:
            tmrescore_counts["WITHOUT_PROPOSAL"] += 1
        if _has_automatic_assessment(fields, automatic_assessment_id_set):
            automatic_assessment_counts["WITH_AUTOMATIC_ASSESSMENT"] += 1
        else:
            automatic_assessment_counts["WITHOUT_AUTOMATIC_ASSESSMENT"] += 1
        if attributed_before_days is not None and _matches_attribution_age(
            fields,
            attributed_before_days,
            attribution_mode,
            now_ms,
        ):
            attribution_age_count += 1

    result["tmrescore"] = tmrescore_counts
    result["automatic_assessment"] = automatic_assessment_counts
    result["attribution_age"] = attribution_age_count
    return result


def build_task_group_query_index(groups: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [{"group": group, "fields": _group_list_fields(group)} for group in groups]
    return {
        "version": TASK_GROUP_QUERY_INDEX_VERSION,
        "rows": rows,
        "total": len(groups),
        "counts": _build_counts(rows),
        "query_cache": {},
    }


def _is_task_group_query_index(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("version") == TASK_GROUP_QUERY_INDEX_VERSION
        and isinstance(value.get("rows"), list)
        and isinstance(value.get("total"), int)
        and isinstance(value.get("counts"), dict)
    )


def get_or_build_task_group_query_index(task: dict[str, Any]) -> dict[str, Any]:
    existing = task.get("_group_query_index")
    if _is_task_group_query_index(existing):
        return existing

    groups = task.get("result")
    if not isinstance(groups, list):
        groups = []

    index = build_task_group_query_index(groups)
    task["_group_query_index"] = index
    return index


def _query_cache_key(
    *,
    q: str,
    lifecycle: list[str],
    inconsistency_reason: list[str],
    analysis: list[str],
    tag: str,
    vuln_id: str,
    component: str,
    assignee: str,
    dependency: list[str],
    versions: list[str],
    cvss_mismatch: bool,
    attributed_before_days: int | None,
    attribution_mode: str,
    tmrescore: list[str],
    tmrescore_proposal_ids: list[str],
    automatic_assessment: list[str],
    automatic_assessment_ids: list[str],
    sort_by: str,
    sort_order: str,
    now_ms: int,
) -> tuple[Any, ...]:
    attribution_day_bucket = (
        now_ms // DAY_MS
        if attributed_before_days is not None
        else None
    )
    return (
        _lower(q),
        _normalized_upper_tuple(lifecycle),
        _normalized_upper_tuple(inconsistency_reason),
        _normalized_upper_tuple(analysis),
        _lower(tag),
        _lower(vuln_id),
        _lower(component),
        _lower(assignee),
        _normalized_upper_tuple(dependency),
        _normalized_lower_tuple(versions),
        bool(cvss_mismatch),
        attributed_before_days,
        attribution_mode,
        attribution_day_bucket,
        _normalized_upper_tuple(tmrescore),
        _normalized_lower_tuple(tmrescore_proposal_ids),
        _normalized_upper_tuple(automatic_assessment),
        _normalized_lower_tuple(automatic_assessment_ids),
        sort_by,
        sort_order,
    )


def _get_query_cache(index: dict[str, Any]) -> dict[tuple[Any, ...], dict[str, Any]]:
    cache = index.setdefault("query_cache", {})
    return cache if isinstance(cache, dict) else {}


def _remember_query_cache_entry(
    cache: dict[tuple[Any, ...], dict[str, Any]],
    key: tuple[Any, ...],
    entry: dict[str, Any],
) -> None:
    if key in cache:
        cache.pop(key, None)
    cache[key] = entry
    while len(cache) > TASK_GROUP_QUERY_CACHE_LIMIT:
        cache.pop(next(iter(cache)))


def query_task_groups(
    groups_or_index: list[dict[str, Any]] | dict[str, Any],
    *,
    q: str,
    lifecycle: list[str],
    analysis: list[str],
    tag: str,
    vuln_id: str,
    component: str,
    assignee: str,
    dependency: list[str],
    versions: list[str],
    cvss_mismatch: bool,
    attributed_before_days: int | None,
    attribution_mode: str,
    tmrescore: list[str],
    tmrescore_proposal_ids: list[str],
    sort_by: str,
    sort_order: str,
    offset: int,
    limit: int,
    cursor: str = "",
    automatic_assessment: list[str] | None = None,
    automatic_assessment_ids: list[str] | None = None,
    inconsistency_reason: list[str] | None = None,
) -> dict[str, Any]:
    now_ms = int(datetime.now().timestamp() * 1000)
    effective_offset = decode_task_group_cursor(cursor) if cursor else offset
    normalized_mode = "younger" if attribution_mode == "younger" else "older"
    if _is_task_group_query_index(groups_or_index):
        index = groups_or_index
    else:
        groups = groups_or_index if isinstance(groups_or_index, list) else []
        index = build_task_group_query_index(groups)
    rows = index["rows"]
    cache = _get_query_cache(index)
    cache_key = _query_cache_key(
        q=q,
        lifecycle=lifecycle,
        inconsistency_reason=inconsistency_reason or [],
        analysis=analysis,
        tag=tag,
        vuln_id=vuln_id,
        component=component,
        assignee=assignee,
        dependency=dependency,
        versions=versions,
        cvss_mismatch=cvss_mismatch,
        attributed_before_days=attributed_before_days,
        attribution_mode=normalized_mode,
        tmrescore=tmrescore,
        tmrescore_proposal_ids=tmrescore_proposal_ids,
        automatic_assessment=automatic_assessment or [],
        automatic_assessment_ids=automatic_assessment_ids or [],
        sort_by=sort_by,
        sort_order=sort_order,
        now_ms=now_ms,
    )
    cached = cache.get(cache_key)

    if cached:
        filtered_indices = cached["indices"]
        counts = cached["counts"]
    else:
        q_terms = tuple(_lower(q).split())
        lifecycle_set = _normalized_upper_set(lifecycle)
        inconsistency_reason_set = _normalized_upper_set(inconsistency_reason or [])
        analysis_set = _normalized_upper_set(analysis)
        tag_terms = tuple(_lower(tag).split())
        vuln_id_terms = tuple(_lower(vuln_id).split())
        component_terms = tuple(_lower(component).split())
        assignee_terms = tuple(_lower(assignee).split())
        dependency_set = _normalized_upper_set(dependency)
        version_set = _normalized_lower_set(versions)
        tmrescore_set = _normalized_upper_set(tmrescore)
        tmrescore_proposal_id_set = _normalized_lower_set(tmrescore_proposal_ids)
        automatic_assessment_set = _normalized_upper_set(automatic_assessment or [])
        automatic_assessment_id_set = _normalized_lower_set(
            automatic_assessment_ids or []
        )
        filtered_with_indices = [
            (index, row)
            for index, row in enumerate(rows)
            if _matches_task_group_fields(
                row["fields"],
                q_terms=q_terms,
                lifecycle=lifecycle_set,
                inconsistency_reason=inconsistency_reason_set,
                analysis=analysis_set,
                tag_terms=tag_terms,
                vuln_id_terms=vuln_id_terms,
                component_terms=component_terms,
                assignee_terms=assignee_terms,
                dependency=dependency_set,
                versions=version_set,
                cvss_mismatch=cvss_mismatch,
                attributed_before_days=attributed_before_days,
                attribution_mode=normalized_mode,
                tmrescore=tmrescore_set,
                tmrescore_proposal_id_set=tmrescore_proposal_id_set,
                automatic_assessment=automatic_assessment_set,
                automatic_assessment_id_set=automatic_assessment_id_set,
                now_ms=now_ms,
            )
        ]
        filtered_with_indices.sort(
            key=lambda item: _task_group_sort_key(item[1], sort_by),
            reverse=sort_order != "asc",
        )
        filtered_indices = [index for index, _ in filtered_with_indices]
        filtered = [row for _, row in filtered_with_indices]
        all_counts = _add_dynamic_counts(
            index["counts"],
            rows,
            tmrescore_proposal_id_set=tmrescore_proposal_id_set,
            automatic_assessment_id_set=automatic_assessment_id_set,
            attributed_before_days=attributed_before_days,
            attribution_mode=normalized_mode,
            now_ms=now_ms,
        )
        filtered_counts = (
            all_counts
            if len(filtered_indices) == len(rows)
            else _add_dynamic_counts(
                _build_counts(filtered),
                filtered,
                tmrescore_proposal_id_set=tmrescore_proposal_id_set,
                automatic_assessment_id_set=automatic_assessment_id_set,
                attributed_before_days=attributed_before_days,
                attribution_mode=normalized_mode,
                now_ms=now_ms,
            )
        )
        counts = {
            "all": all_counts,
            "filtered": filtered_counts,
        }
        _remember_query_cache_entry(
            cache,
            cache_key,
            {
                "indices": filtered_indices,
                "counts": counts,
            },
        )

    filtered_count = len(filtered_indices)
    window_indices = filtered_indices[effective_offset : effective_offset + limit]
    window = [rows[index] for index in window_indices]
    next_offset = effective_offset + len(window_indices)
    next_cursor = (
        encode_task_group_cursor(next_offset)
        if window_indices and next_offset < filtered_count
        else None
    )
    return {
        "items": [row["group"] for row in window],
        "total": index["total"],
        "filtered": filtered_count,
        "counts": counts,
        "offset": effective_offset,
        "limit": limit,
        "cursor": cursor or None,
        "next_cursor": next_cursor,
        "has_more": bool(next_cursor),
        "sort": sort_by,
        "order": sort_order,
    }
