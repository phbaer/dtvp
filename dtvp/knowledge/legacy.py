"""Read-only native evidence for historical tagged or plain DT documentation."""

import json

from dtvp.legacy_dt import decode
from dtvp.rescoring import calculate, original_vectors
from dtvp.storage import canonical, digest

MAX_ANALYSIS_BYTES = 128 * 1024
MAX_TOTAL_BYTES = 512 * 1024
MAX_PROPERTIES = 50
MAX_OBSERVATIONS = 100
MAX_PROPERTY_ENTRIES = 2000
MAX_DEPTH = 24
MAX_NODES = 4000
MAX_RECORDS = 200


def _bounded(value):
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            return False
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return True


def _text(value):
    return value[:500] if isinstance(value, str) else None


def _base(observation, index, property_index):
    reference = {
        "observation_id": _text(observation.get("observation_id")),
        "observation_index": index,
        "property_index": property_index,
        "property": "dtvp:dt-analysis",
        "retained_in": "sourcefacts",
    }
    return {
        "id": digest(canonical(reference)),
        "kind": "legacy_dt_analysis",
        "format": "dtvp.legacy-evidence/1",
        "source": _text(observation.get("source")),
        "vulnerability_id": _text(observation.get("identifier")),
        "component_ref": _text(observation.get("ref")),
        "original_source_ref": reference,
        "approved": False,
        "authenticated_identity": False,
        "identity_verification": "historical_source_labels_only",
    }


def _unparsed(base, reason, raw=None, status="unparsed"):
    return {
        **base,
        "status": status,
        "errors": [reason],
        "proposed_applicability": None,
        "records": [],
        "current_records": [],
        "comments": [],
        "scoring_proposals": [],
        "conflicting": False,
        "raw_excerpt": raw[:2000] if isinstance(raw, str) else None,
        "original_retained": True,
    }


def _scoring(record, bases, index):
    score, vector = record.get("rescored_score"), record.get("rescored_vector")
    if score is None and not vector and "rescored" not in record.get("metadata", {}):
        return None
    blockers, proposal = [], None
    if not vector:
        blockers.append("legacy_score_without_vector")
    else:
        for base in bases:
            try:
                proposal = calculate(base["vector"], vector)
                break
            except ValueError, TypeError, KeyError:
                pass
        if proposal is None:
            blockers.append("legacy_vector_unsupported_or_original_base_mismatch")
        elif score is not None and proposal["score"] != score:
            blockers.append("legacy_score_vector_mismatch")
    if score is None:
        blockers.append("legacy_score_missing_or_invalid")
    return {
        "record_index": index,
        "team": record.get("team"),
        "claimed_score": score,
        "claimed_vector": vector,
        "proposal": proposal,
        "usable_for_preview": bool(proposal and not blockers),
        "eligible": False,
        "requires_coordinator_publication": True,
        "blockers": blockers,
        "historical": record.get("historical", False),
    }


def _normalized_record(record, index):
    gaps = [name for name in ("assessor", "reviewer") if not record.get(name)]
    return {
        **record,
        "record_index": index,
        "authenticated_identity": False,
        "identity_gaps": gaps,
        "identity_verification": "historical_source_labels_only",
        "approved": False,
    }


def _parse(base, raw, advisory):
    if not isinstance(raw, str):
        return _unparsed(base, "DT analysis property must contain JSON text")
    if len(raw) > MAX_ANALYSIS_BYTES or len(raw.encode()) > MAX_ANALYSIS_BYTES:
        return _unparsed(
            base, "DT analysis exceeds the supported size; original retained", raw, "limited"
        )
    try:
        analysis = json.loads(raw)
    except ValueError, RecursionError:
        return _unparsed(base, "DT analysis JSON could not be decoded", raw)
    if not isinstance(analysis, dict):
        return _unparsed(base, "DT analysis JSON must be an object", raw)
    if not _bounded(analysis):
        return _unparsed(
            base, "DT analysis nesting or item limit exceeded; original retained", raw, "limited"
        )
    try:
        parsed = decode(analysis)
    except ValueError, TypeError, OverflowError, RecursionError:
        return _unparsed(
            base, "DT analysis fields could not be interpreted; original retained", raw
        )
    if parsed is None:
        nested = analysis.get("analysis")
        effective = nested if isinstance(nested, dict) else analysis
        comments = analysis.get(
            "comments", analysis.get("analysisComments", effective.get("analysisComments", []))
        )
        return {
            **base,
            "status": "empty" if not comments else "parsed",
            "legacy_format": "plain-dt",
            "proposed_applicability": None,
            "records": [],
            "current_records": [],
            "comments": comments,
            "scoring_proposals": [],
            "conflicting": False,
            "raw_text": "",
            "errors": [
                "No assessment state or text; any source comments remain historical assertions"
            ],
            "original_retained": True,
        }
    if not _bounded(parsed) or len(parsed["records"]) > MAX_RECORDS:
        return _unparsed(
            base, "Decoded DT history exceeds the supported nesting or record limit", raw, "limited"
        )
    records = [_normalized_record(record, index) for index, record in enumerate(parsed["records"])]
    current = [_normalized_record(record, record["index"]) for record in parsed["current_records"]]
    states = {record["state"] for record in current if record.get("state")}
    conflicting = parsed["conflicting"] or len(states) > 1
    ratings = advisory.get("ratings", [])
    if not isinstance(ratings, list) or any(not isinstance(value, dict) for value in ratings[:100]):
        bases = []
        parsed["errors"].append("Source ratings unavailable; legacy scoring remains unverified")
    elif len(ratings) > 100:
        bases = []
        parsed["errors"].append(
            "Source rating inspection limit exceeded; legacy scoring remains unverified"
        )
    else:
        bases = original_vectors([advisory])
    proposals = [_scoring(record, bases, index) for index, record in enumerate(records)]
    return {
        **base,
        "status": "parsed",
        "legacy_format": parsed["format"],
        "proposed_applicability": None if conflicting else parsed["state"],
        "source_applicability": parsed["state"],
        "source_state": parsed["source_state"],
        "documented": parsed["documented"],
        "pending_review": parsed["pending_review"],
        "conflicting": conflicting,
        "records": records,
        "current_records": current,
        "comments": parsed["comments"],
        "raw_text": parsed["raw_text"],
        "shared_text": parsed["shared_text"],
        "ssvc": parsed["ssvc"],
        "suppressed": parsed["suppressed"],
        "errors": parsed["errors"],
        "scoring_proposals": [proposal for proposal in proposals if proposal],
        "original_retained": True,
    }


def legacy_claims(observations):
    """Expose bounded legacy evidence; raw originals stay in source observations.

    Human v3 assessment/review state and source Base ratings are never mutated.
    Imported labels never establish authenticated authorship or approval.
    """
    claims, total_bytes, encountered, inspected = [], 0, 0, 0
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            continue
        if index >= MAX_OBSERVATIONS:
            claims.append(
                _unparsed(
                    _base(observation, index, None),
                    "Legacy observation inspection limit reached; originals retained in sourcefacts",
                    status="limited",
                )
            )
            return claims
        advisory = observation.get("advisory", {})
        if not isinstance(advisory, dict):
            continue
        properties = advisory.get("properties", [])
        if not isinstance(properties, list):
            claims.append(
                _unparsed(
                    _base(observation, index, None),
                    "Advisory properties are not an array; original retained",
                )
            )
            continue
        for property_index, entry in enumerate(properties):
            inspected += 1
            if inspected > MAX_PROPERTY_ENTRIES:
                claims.append(
                    _unparsed(
                        _base(observation, index, property_index),
                        "Legacy property inspection limit reached; originals retained in sourcefacts",
                        status="limited",
                    )
                )
                return claims
            if not isinstance(entry, dict) or entry.get("name") != "dtvp:dt-analysis":
                continue
            encountered += 1
            base = _base(observation, index, property_index)
            if encountered > MAX_PROPERTIES or total_bytes >= MAX_TOTAL_BYTES:
                claims.append(
                    _unparsed(
                        base,
                        "Legacy evidence output limit reached; remaining originals retained in sourcefacts",
                        status="limited",
                    )
                )
                return claims
            raw = entry.get("value")
            if isinstance(raw, str):
                total_bytes += (
                    MAX_ANALYSIS_BYTES
                    if len(raw) > MAX_ANALYSIS_BYTES
                    else min(len(raw.encode()), MAX_ANALYSIS_BYTES)
                )
            claims.append(_parse(base, raw, advisory))
    return claims
