"""Explicit offline curated CPE source replacement, not upstream synchronization."""

import base64
import binascii
import copy
import csv
import io
from collections import Counter
from typing import Literal

from pydantic import Field, field_validator

from dtvp.knowledge.cpe import current_discovery_policy, parse_purl, policy_ref, validate_cpe
from dtvp.knowledge.cpe_ranking import DictionaryRecord, rank_candidates
from dtvp.knowledge.cpe_refresh import CpeAcquisition, validate_acquisition
from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Sha, Update
from dtvp.knowledge.legacy_archive import strict_json
from dtvp.knowledge.service import validate_time
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_BYTES = 2 * 1024 * 1024
MAX_BODY = 3 * 1024 * 1024
MAX_RECORDS = 2000
CSV_COLUMNS = ("name", "cpe", "status", "options", "package_type", "group", "author", "purl")
LIMITATIONS = [
    "Offline curated sources of at most 2,000 records; not a complete national CPE dictionary or full standalone-service parity.",
    "Expected-head CAS controls replacement; a declared revision/time does not prove upstream freshness or chronology.",
    "Source, publisher, mapping status and author claims remain attributed and unverified; no native approval or identity adoption occurs.",
    "CSV captures are point-in-time mapping claims, not reconstructed Git history or source events; missing PURLs are not guessed from names.",
    "CPE identity and ranking do not establish vulnerability applicability, affected ranges or complete discovery.",
]


class CpeSourceInput(RequestModel):
    request_id: Name
    expected: Sha | None
    kind: Literal["dictionary", "mapping_history"]
    source: Name
    revision: Name
    occurred_at: str
    reason: str = Field(min_length=1, max_length=2000)
    artifact_sha256: Sha
    content_base64: str = Field(min_length=1, max_length=4 * ((MAX_BYTES + 2) // 3))

    acquisition: CpeAcquisition | None = None

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value):
        return validate_time(value)

    @field_validator("reason")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("A meaningful source replacement reason is required")
        return value


class CpeSourceApply(CpeSourceInput):
    preview_digest: Sha


def _input_payload(data):
    payload = data.model_dump(mode="json")
    if payload.get("acquisition") is None:
        payload.pop("acquisition", None)
    return payload


def identity(project_id, actor_id, data):
    return digest(canonical([project_id, actor_id, data.request_id])), digest(
        canonical(["cpe.offline-source/1", project_id, actor_id, _input_payload(data)])
    )


def decode(data):
    try:
        raw = base64.b64decode(data.content_base64, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Invalid source base64") from error
    if len(raw) > MAX_BYTES or digest(raw) != data.artifact_sha256:
        raise ValueError("Offline source bytes exceed the bound or declared digest differs")
    return raw


def dictionary(raw, source):
    payload = strict_json(raw)
    projected = 0
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict) and isinstance(payload.get("products"), list):
        if len(payload["products"]) > MAX_RECORDS:
            raise ValueError("Curated dictionary exceeds 2,000 records")
        entries = []
        for product in payload["products"]:
            if not isinstance(product, dict) or not isinstance(product.get("cpe"), dict):
                raise ValueError("Expected NVD-shaped products containing explicit cpe objects")
            original = product["cpe"]
            projected += len(set(original) - set(DictionaryRecord.model_fields))
            entries.append(
                {
                    key: value
                    for key, value in original.items()
                    if key in DictionaryRecord.model_fields
                }
            )
    else:
        raise ValueError(
            "Expected an explicit dictionary record array or bounded NVD-shaped products"
        )
    if len(entries) > MAX_RECORDS:
        raise ValueError("Curated dictionary exceeds 2,000 records")
    normalized, names, ids = [], set(), set()
    for value in entries:
        if not isinstance(value, dict):
            raise ValueError("Dictionary records must be objects")
        record = DictionaryRecord.model_validate({"source": source, **value}).model_dump(
            mode="json"
        )
        validate_cpe(record["cpeName"])
        if record["cpeName"] in names or (record["cpeNameId"] and record["cpeNameId"] in ids):
            raise ValueError("Dictionary names and supplied IDs must be unique")
        names.add(record["cpeName"])
        ids.add(record["cpeNameId"])
        normalized.append(record)
    return sorted(normalized, key=canonical), {"projected_extra_dictionary_fields": projected}


def mapping_history(raw):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError as error:
        raise ValueError("Mapping history must be UTF-8 CSV") from error
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    if (
        reader.fieldnames is None
        or len(reader.fieldnames) != len(set(reader.fieldnames))
        or set(reader.fieldnames) != set(CSV_COLUMNS)
    ):
        raise ValueError("Expected standalone cpeservice eight-column mapping CSV")
    rows, names, losses = [], set(), Counter()
    try:
        for row in reader:
            if (
                len(rows) >= MAX_RECORDS
                or None in row
                or any(value is None or len(value) > 6000 for value in row.values())
            ):
                raise ValueError("Mapping history exceeds row/field bounds or is malformed")
            if not row["name"] or row["name"] in names:
                raise ValueError("Mapping history names must be explicit and unique")
            names.add(row["name"])
            status = "explicit_identity_unverified"
            try:
                parse_purl(row["purl"])
                validate_cpe(row["cpe"])
            except ValueError:
                status = "identity_unresolved_no_name_guess"
                losses[status] += 1
            rows.append(
                {
                    "claim": row,
                    "identity_status": status,
                    "trust": "historical_unverified",
                    "native_approval": False,
                }
            )
    except csv.Error as error:
        raise ValueError("Malformed bounded mapping CSV") from error
    return rows, dict(losses)


def _candidate(journal, *, project_id, actor_id, data):
    state, current = current_discovery_policy(journal, project_id)
    if state != data.expected:
        raise Conflict("CPE policy changed; prepare the offline source replacement again")
    raw = decode(data)
    if data.acquisition is not None:
        if data.kind != "dictionary" or data.acquisition.artifact_sha256 != data.artifact_sha256:
            raise ValueError("CPE acquisition must bind the exact dictionary artifact")
        validate_acquisition(raw, data.acquisition)
    rows, losses = (
        dictionary(raw, data.source) if data.kind == "dictionary" else mapping_history(raw)
    )
    config = copy.deepcopy(current)
    sources = config.setdefault("offline_sources", {})
    previous = sources.get(data.kind)
    metadata = {
        "kind": data.kind,
        "source": data.source,
        "revision": data.revision,
        "occurred_at": data.occurred_at,
        "artifact_sha256": data.artifact_sha256,
        "bytes": len(raw),
        "records": len(rows),
        "content_digest": digest(canonical(rows)),
        "verification": "imported_claim_not_verified",
        "ordering": "expected_head_CAS_only",
        "losses": losses,
    }
    if data.acquisition is not None:
        metadata["acquisition"] = data.acquisition.model_dump(mode="json")
        metadata["coverage"] = "complete_returned_keyword_subset_not_full_dictionary"
        metadata["verification"] = "declared_capture_provenance_not_signed_publisher_authentication"
    sources[data.kind] = metadata
    config["retained_dictionary" if data.kind == "dictionary" else "retained_mapping_history"] = (
        rows
    )
    config["offline_source_limitations"] = LIMITATIONS
    sections = {name: {} for name in SECTIONS}
    sections["inventory"]["cpe:configuration"] = config
    sections["history"]["cpe:offline-source"] = {
        **metadata,
        "reason": data.reason,
        "actor_id": actor_id,
        "claims_verification": "historical_unverified",
        "native_approval": False,
    }
    result = {
        "format": "dtvp.cpe-offline-source-preview/1",
        "committed": False,
        "project_id": project_id,
        "policy_state": state,
        "source": metadata,
        "replaces": previous,
        "native_approvals": 0,
        "identity_adoptions": 0,
        "mapping_rules_changed": False,
        "catalog_changed": False,
        "limitations": LIMITATIONS,
    }
    result["preview_digest"] = digest(
        canonical(
            [
                result,
                actor_id,
                {
                    key: value
                    for key, value in _input_payload(data).items()
                    if key != "preview_digest"
                },
                sections,
            ]
        )
    )
    return result, sections, raw


def preview_source(journal, **kwargs):
    return _candidate(journal, **kwargs)[0]


def apply_source(journal, *, project_id, actor_id, data):
    request_id, fingerprint = identity(project_id, actor_id, data)
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    result, sections, raw = _candidate(journal, project_id=project_id, actor_id=actor_id, data=data)
    if data.preview_digest != result["preview_digest"]:
        raise Conflict("Offline source preview does not match the captured inputs")
    artifacts = set(journal.state(data.expected).artifacts if data.expected else [])
    artifacts.add(journal.objects.put(raw))
    state = journal.snapshot(
        project_id=project_id,
        version="@cpe",
        actor_id=actor_id,
        reason="Import offline curated CPE source",
        sections=sections,
        parents=[data.expected] if data.expected else [],
        artifacts=sorted(artifacts),
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=policy_ref(project_id), expected=data.expected, target=state)],
    )


def retained_policy(journal, project_id, selected):
    """Only a bounded retained CPE policy lineage, never arbitrary object hashes."""
    current = journal.resolve(policy_ref(project_id))
    seen, total = set(), 0
    while current and current not in seen:
        if len(seen) >= 1000:
            raise ValueError("Retained CPE policy history exceeds the supported scan bound")
        total += journal.objects.path(current).stat().st_size
        if total > 64 * 1024 * 1024:
            raise ValueError("Retained CPE policy history exceeds the supported byte bound")
        seen.add(current)
        state = journal.state(current)
        if state.project_id != project_id:
            raise ValueError("CPE policy history has inconsistent project scope")
        if current == selected:
            section_sha = state.sections["inventory"]
            total += journal.objects.path(section_sha).stat().st_size
            if total > 64 * 1024 * 1024:
                raise ValueError("Retained CPE policy exceeds the supported byte bound")
            pointers = journal.load(section_sha)["records"]
            config_sha = pointers["cpe:configuration"]
            total += journal.objects.path(config_sha).stat().st_size
            if total > 64 * 1024 * 1024:
                raise ValueError("Retained CPE policy exceeds the supported byte bound")
            return journal.load(config_sha)
        current = state.parents[0] if state.parents else None
    raise ValueError("CPE policy unavailable in this product line")


def source_report(journal, *, project_id, policy, kind, offset=0, limit=50):
    if kind not in {"dictionary", "mapping_history"} or offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid offline source page")
    config = retained_policy(journal, project_id, policy)
    rows = config.get(
        "retained_dictionary" if kind == "dictionary" else "retained_mapping_history", []
    )
    return {
        "policy_state": policy,
        "source": config.get("offline_sources", {}).get(kind),
        "items": rows[offset : offset + limit],
        "total": len(rows),
        "next_offset": offset + limit if offset + limit < len(rows) else None,
        "limitations": LIMITATIONS,
    }


def rank_retained(journal, *, project_id, policy, component, offset=0, limit=50):
    config = retained_policy(journal, project_id, policy)
    if "retained_dictionary" not in config:
        raise ValueError("Selected CPE policy has no retained curated dictionary")
    return {
        "policy_state": policy,
        "source": config["offline_sources"]["dictionary"],
        "report": rank_candidates(
            component,
            config["retained_dictionary"],
            config["catalog"],
            config["rules"],
            offset=offset,
            limit=limit,
        ),
    }
