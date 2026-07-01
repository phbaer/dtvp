import base64
import json
from datetime import datetime
from functools import cmp_to_key
from typing import Any


DAY_MS = 24 * 60 * 60 * 1000
TASK_GROUP_QUERY_INDEX_VERSION = 2
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
    assignees = _string_list(group.get("assignees") or [])
    component_names = _component_names_for_group(group)
    versions = _versions_for_group(group)
    base_score = group.get("cvss_score")
    if base_score is None:
        base_score = group.get("cvss", 0)
    rescored_score = group.get("rescored_cvss")
    if rescored_score is None:
        rescored_score = base_score

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
        ]
        if value
    )

    return {
        "id": str(group.get("id") or ""),
        "id_lower": _lower(group.get("id")),
        "aliases": aliases,
        "aliases_lower": [_lower(value) for value in aliases],
        "tags": tags,
        "tags_lower": [_lower(value) for value in tags],
        "first_tag": tags[0] if tags else "",
        "component_names": component_names,
        "component_names_lower": [_lower(value) for value in component_names],
        "assignees": assignees,
        "assignees_lower": [_lower(value) for value in assignees],
        "versions": versions,
        "searchable_text": searchable_text,
        "lifecycle": str(metadata.get("lifecycle") or "OPEN"),
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
    }


def _matches_lifecycle(fields: dict[str, Any], filters: list[str]) -> bool:
    if not filters:
        return True
    normalized = {item.upper() for item in filters}
    lifecycle = fields["lifecycle"]
    return (
        ("OPEN" in normalized and fields["is_open"])
        or ("ASSESSED" in normalized and lifecycle == "ASSESSED")
        or ("ASSESSED_LEGACY" in normalized and lifecycle == "ASSESSED_LEGACY")
        or ("INCOMPLETE" in normalized and lifecycle == "INCOMPLETE")
        or ("INCONSISTENT" in normalized and lifecycle == "INCONSISTENT")
        or ("NEEDS_APPROVAL" in normalized and fields["is_pending"])
    )


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


def _matches_all_terms(values: list[str], query: str) -> bool:
    terms = _lower(query).split()
    if not terms:
        return True
    return all(any(term in value for value in values) for term in terms)


def _matches_versions(values: list[str], filters: list[str]) -> bool:
    if not filters:
        return True
    normalized_values = {value.lower() for value in values}
    return any(version.lower() in normalized_values for version in filters)


def _matches_tmrescore_proposal(
    fields: dict[str, Any],
    filters: list[str],
    proposal_ids: list[str],
) -> bool:
    if not filters:
        return True

    normalized_filters = {item.upper() for item in filters}
    if {"WITH_PROPOSAL", "WITHOUT_PROPOSAL"}.issubset(normalized_filters):
        return True

    proposal_id_set = {_lower(value) for value in proposal_ids if _lower(value)}
    candidate_ids = {fields["id_lower"], *fields["aliases_lower"]}
    has_proposal = any(candidate_id in proposal_id_set for candidate_id in candidate_ids)

    return (
        ("WITH_PROPOSAL" in normalized_filters and has_proposal)
        or ("WITHOUT_PROPOSAL" in normalized_filters and not has_proposal)
    )


def _matches_task_group_fields(
    fields: dict[str, Any],
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
    now_ms: int,
) -> bool:
    if q and not all(term in fields["searchable_text"] for term in _lower(q).split()):
        return False
    if not _matches_lifecycle(fields, lifecycle):
        return False
    if analysis and fields["technical_state"] not in {item.upper() for item in analysis}:
        return False
    if tag and not _matches_all_terms(fields["tags_lower"], tag):
        return False
    if vuln_id and not _matches_all_terms(
        [fields["id_lower"], *fields["aliases_lower"]],
        vuln_id,
    ):
        return False
    if component and not _matches_all_terms(fields["component_names_lower"], component):
        return False
    if assignee and not _matches_all_terms(fields["assignees_lower"], assignee):
        return False
    if dependency and fields["dependency_relationship"] not in {
        item.upper() for item in dependency
    }:
        return False
    if not _matches_versions(fields["versions"], versions):
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
    if not _matches_tmrescore_proposal(fields, tmrescore, tmrescore_proposal_ids):
        return False
    return True


def _compare_task_group_fields(
    a: dict[str, Any],
    b: dict[str, Any],
    sort_by: str,
) -> int:
    comparison = 0

    if sort_by == "analysis":
        comparison = ANALYSIS_STATE_ORDER.get(
            a["technical_state"], 99
        ) - ANALYSIS_STATE_ORDER.get(b["technical_state"], 99)
    elif sort_by == "tags":
        comparison = (a["first_tag"] > b["first_tag"]) - (
            a["first_tag"] < b["first_tag"]
        )
    elif sort_by == "severity":
        comparison = b["base_severity_rank"] - a["base_severity_rank"]
    elif sort_by == "rescored-severity":
        comparison = b["rescored_severity_rank"] - a["rescored_severity_rank"]
    elif sort_by == "score":
        comparison = (a["base_score"] > b["base_score"]) - (
            a["base_score"] < b["base_score"]
        )
    elif sort_by == "rescored":
        comparison = (a["rescored_score"] > b["rescored_score"]) - (
            a["rescored_score"] < b["rescored_score"]
        )
    elif sort_by == "id":
        comparison = (a["id"] > b["id"]) - (a["id"] < b["id"])

    if comparison == 0:
        comparison = (a["id"] > b["id"]) - (a["id"] < b["id"])
    return comparison


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


def _increment(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def _normalized_upper_tuple(values: list[str]) -> tuple[str, ...]:
    return tuple(sorted(str(value or "").strip().upper() for value in values if str(value or "").strip()))


def _normalized_lower_tuple(values: list[str]) -> tuple[str, ...]:
    return tuple(sorted(_lower(value) for value in values if _lower(value)))


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
    }


def _copy_counts(counts: dict[str, Any]) -> dict[str, Any]:
    return {
        **counts,
        "lifecycle": dict(counts.get("lifecycle", {})),
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
    }


def _has_tmrescore_proposal(
    fields: dict[str, Any],
    proposal_ids: list[str],
) -> bool:
    proposal_id_set = {_lower(value) for value in proposal_ids if _lower(value)}
    if not proposal_id_set:
        return False
    candidate_ids = {fields["id_lower"], *fields["aliases_lower"]}
    return any(candidate_id in proposal_id_set for candidate_id in candidate_ids)


def _add_dynamic_counts(
    counts: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    tmrescore_proposal_ids: list[str],
    attributed_before_days: int | None,
    attribution_mode: str,
    now_ms: int,
) -> dict[str, Any]:
    result = _copy_counts(counts)
    tmrescore_counts = _empty_tmrescore_counts()
    attribution_age_count = 0

    for row in rows:
        fields = row["fields"]
        if _has_tmrescore_proposal(fields, tmrescore_proposal_ids):
            tmrescore_counts["WITH_PROPOSAL"] += 1
        else:
            tmrescore_counts["WITHOUT_PROPOSAL"] += 1
        if attributed_before_days is not None and _matches_attribution_age(
            fields,
            attributed_before_days,
            attribution_mode,
            now_ms,
        ):
            attribution_age_count += 1

    result["tmrescore"] = tmrescore_counts
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
        sort_by=sort_by,
        sort_order=sort_order,
        now_ms=now_ms,
    )
    cached = cache.get(cache_key)

    if cached:
        filtered_indices = cached["indices"]
        counts = cached["counts"]
    else:
        filtered_with_indices = [
            (index, row)
            for index, row in enumerate(rows)
            if _matches_task_group_fields(
                row["fields"],
                q=q,
                lifecycle=lifecycle,
                analysis=analysis,
                tag=_lower(tag),
                vuln_id=_lower(vuln_id),
                component=_lower(component),
                assignee=_lower(assignee),
                dependency=dependency,
                versions=versions,
                cvss_mismatch=cvss_mismatch,
                attributed_before_days=attributed_before_days,
                attribution_mode=normalized_mode,
                tmrescore=tmrescore,
                tmrescore_proposal_ids=tmrescore_proposal_ids,
                now_ms=now_ms,
            )
        ]
        direction = 1 if sort_order == "asc" else -1
        filtered_with_indices.sort(
            key=cmp_to_key(
                lambda left, right: direction
                * _compare_task_group_fields(left[1]["fields"], right[1]["fields"], sort_by)
            )
        )
        filtered_indices = [index for index, _ in filtered_with_indices]
        filtered = [row for _, row in filtered_with_indices]
        counts = {
            "all": _add_dynamic_counts(
                index["counts"],
                rows,
                tmrescore_proposal_ids=tmrescore_proposal_ids,
                attributed_before_days=attributed_before_days,
                attribution_mode=normalized_mode,
                now_ms=now_ms,
            ),
            "filtered": _add_dynamic_counts(
                _build_counts(filtered),
                filtered,
                tmrescore_proposal_ids=tmrescore_proposal_ids,
                attributed_before_days=attributed_before_days,
                attribution_mode=normalized_mode,
                now_ms=now_ms,
            ),
        }
        _remember_query_cache_entry(
            cache,
            cache_key,
            {
                "indices": filtered_indices,
                "counts": counts,
            },
        )

    filtered = [rows[index] for index in filtered_indices]
    window = filtered[effective_offset : effective_offset + limit]
    next_offset = effective_offset + len(window)
    next_cursor = (
        encode_task_group_cursor(next_offset)
        if window and next_offset < len(filtered)
        else None
    )
    return {
        "items": [row["group"] for row in window],
        "total": index["total"],
        "filtered": len(filtered),
        "counts": counts,
        "offset": effective_offset,
        "limit": limit,
        "cursor": cursor or None,
        "next_cursor": next_cursor,
        "has_more": bool(next_cursor),
        "sort": sort_by,
        "order": sort_order,
    }
