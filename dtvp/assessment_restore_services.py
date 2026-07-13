import re
from typing import Any, Optional


ASSESSMENT_RESTORE_REASON_MISSING_RESCORING_VECTOR = "MISSING_RESCORING_VECTOR"
ASSESSMENT_RESTORE_STATUS_RECOVERABLE = "recoverable"
ASSESSMENT_RESTORE_STATUS_AMBIGUOUS = "ambiguous"
ASSESSMENT_RESTORE_STATUS_NO_HISTORY = "no_history"

_RE_SCORE = re.compile(r"\[Rescored:\s*([\d.]+)\]")
_RE_VECTOR = re.compile(r"\[Rescored Vector:\s*([^\]]+)\]")


def _analysis_state(analysis: dict[str, Any] | None) -> str:
    if not analysis:
        return "NOT_SET"
    return str(
        analysis.get("analysisState")
        or analysis.get("analysis_state")
        or analysis.get("state")
        or "NOT_SET"
    ).upper()


def _analysis_details(analysis: dict[str, Any] | None) -> str:
    if not analysis:
        return ""
    return str(
        analysis.get("analysisDetails")
        or analysis.get("analysis_details")
        or analysis.get("details")
        or ""
    )


def _analysis_comments(analysis: dict[str, Any] | None) -> list[Any]:
    if not analysis:
        return []
    for key in ("analysisComments", "analysis_comments", "comments"):
        value = analysis.get(key)
        if isinstance(value, list):
            return value
    return []


def _parse_score(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _comment_text(comment: Any) -> str:
    if isinstance(comment, dict):
        return str(comment.get("comment") or comment.get("text") or "")
    return str(comment or "")


def _comment_timestamp(comment: Any) -> Any:
    if isinstance(comment, dict):
        return comment.get("timestamp") or comment.get("date") or comment.get("created")
    return None


def _commenter(comment: Any) -> str | None:
    if isinstance(comment, dict):
        value = comment.get("commenter") or comment.get("user") or comment.get("author")
        return str(value) if value else None
    return None


def _timestamp_sort_key(value: Any) -> tuple[int, float, str]:
    if value is None:
        return (0, 0.0, "")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (1, float(value), "")
    raw = str(value)
    try:
        return (1, float(raw), "")
    except ValueError:
        return (1, 0.0, raw)


def _historical_rescoring_sources(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for index, comment in enumerate(_analysis_comments(analysis)):
        text = _comment_text(comment)
        if not text:
            continue

        all_score_matches = list(_RE_SCORE.finditer(text))
        for vector_match in _RE_VECTOR.finditer(text):
            preceding_scores = [
                match for match in all_score_matches if match.start() < vector_match.start()
            ]
            score_match = (
                preceding_scores[-1]
                if preceding_scores
                else (all_score_matches[0] if all_score_matches else None)
            )
            sources.append(
                {
                    "vector": vector_match.group(1).strip(),
                    "score": _parse_score(score_match.group(1) if score_match else None),
                    "timestamp": _comment_timestamp(comment),
                    "commenter": _commenter(comment),
                    "comment_index": index,
                }
            )

    sources.sort(
        key=lambda source: (
            _timestamp_sort_key(source.get("timestamp")),
            int(source.get("comment_index") or 0),
        ),
        reverse=True,
    )
    return sources


def _has_strictly_newest_vector(sources: list[dict[str, Any]]) -> bool:
    if not sources:
        return False

    newest_source = sources[0]
    newest_vector = newest_source.get("vector")
    newest_timestamp_key = _timestamp_sort_key(newest_source.get("timestamp"))
    if not newest_vector or newest_timestamp_key[0] == 0:
        return False

    for source in sources[1:]:
        if source.get("vector") == newest_vector:
            continue
        timestamp_key = _timestamp_sort_key(source.get("timestamp"))
        if timestamp_key[0] == 0 or timestamp_key >= newest_timestamp_key:
            return False
    return True


def build_missing_rescoring_vector_restore_candidate(
    analysis: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not analysis or _analysis_state(analysis) == "NOT_SET":
        return None

    details = _analysis_details(analysis)
    if not details:
        return None
    if _RE_VECTOR.search(details):
        return None

    current_score_match = _RE_SCORE.search(details)
    current_score = _parse_score(current_score_match.group(1) if current_score_match else None)
    historical_sources = _historical_rescoring_sources(analysis)

    # Without a current score or an audit-trail vector there is no reliable
    # signal that rescoring metadata was lost.
    if current_score is None and not historical_sources:
        return None

    unique_vectors = sorted({source["vector"] for source in historical_sources})
    newest_source = historical_sources[0] if historical_sources else None
    newest_score = _parse_score(newest_source.get("score")) if newest_source else None
    newest_matches_current_score = (
        current_score is None
        or newest_score is None
        or abs(current_score - newest_score) < 0.0001
    )

    if newest_source is not None and (
        len(unique_vectors) == 1
        or (
            newest_matches_current_score
            and _has_strictly_newest_vector(historical_sources)
        )
    ):
        status = ASSESSMENT_RESTORE_STATUS_RECOVERABLE
        restored_vector = newest_source["vector"]
        restored_score = (
            current_score
            if current_score is not None
            else newest_score
        )
    elif len(unique_vectors) > 1:
        status = ASSESSMENT_RESTORE_STATUS_AMBIGUOUS
        restored_vector = None
        restored_score = current_score
    else:
        status = ASSESSMENT_RESTORE_STATUS_NO_HISTORY
        restored_vector = None
        restored_score = current_score

    return {
        "reason": ASSESSMENT_RESTORE_REASON_MISSING_RESCORING_VECTOR,
        "status": status,
        "current_score": current_score,
        "restored_score": restored_score,
        "restored_vector": restored_vector,
        "candidate_vectors": unique_vectors,
        "source": (
            {
                "timestamp": newest_source.get("timestamp"),
                "commenter": newest_source.get("commenter"),
                "comment_index": newest_source.get("comment_index"),
            }
            if newest_source
            else None
        ),
    }


def restore_rescoring_tags_in_details(
    details: str,
    *,
    restored_vector: str,
    restored_score: float | None = None,
) -> str:
    if not details or _RE_VECTOR.search(details):
        return details

    vector_tag = f"[Rescored Vector: {restored_vector}]"
    score_match = _RE_SCORE.search(details)
    if score_match:
        return (
            details[: score_match.end()]
            + f" {vector_tag}"
            + details[score_match.end() :]
        )

    tags = [vector_tag]
    if restored_score is not None:
        tags.insert(0, f"[Rescored: {restored_score:g}]")
    return f"{' '.join(tags)}\n\n{details}".strip()


def update_component_restore_metadata(component: dict[str, Any]) -> dict[str, Any] | None:
    analysis = {
        "analysisState": component.get("analysis_state") or component.get("analysisState"),
        "analysisDetails": component.get("analysis_details") or component.get("analysisDetails"),
        "analysisComments": component.get("analysis_comments")
        or component.get("analysisComments")
        or [],
    }
    candidate = build_missing_rescoring_vector_restore_candidate(analysis)
    if candidate:
        component["assessment_restore"] = candidate
    else:
        component.pop("assessment_restore", None)
    return candidate


def refresh_group_restore_metadata(group: dict[str, Any]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for affected_version in group.get("affected_versions") or []:
        for component in affected_version.get("components") or []:
            if not isinstance(component, dict):
                continue
            candidate = update_component_restore_metadata(component)
            if candidate:
                candidates.append(candidate)

    reasons = sorted({candidate["reason"] for candidate in candidates})
    recoverable_count = sum(
        1
        for candidate in candidates
        if candidate.get("status") == ASSESSMENT_RESTORE_STATUS_RECOVERABLE
    )
    statuses = {candidate.get("status") for candidate in candidates}
    if ASSESSMENT_RESTORE_STATUS_RECOVERABLE in statuses:
        status = ASSESSMENT_RESTORE_STATUS_RECOVERABLE
    elif ASSESSMENT_RESTORE_STATUS_AMBIGUOUS in statuses:
        status = ASSESSMENT_RESTORE_STATUS_AMBIGUOUS
    elif ASSESSMENT_RESTORE_STATUS_NO_HISTORY in statuses:
        status = ASSESSMENT_RESTORE_STATUS_NO_HISTORY
    else:
        status = None

    group["assessment_restore_count"] = len(candidates)
    group["assessment_restore_recoverable_count"] = recoverable_count
    group["assessment_restore_reasons"] = reasons
    group["assessment_restore_status"] = status
    return group
