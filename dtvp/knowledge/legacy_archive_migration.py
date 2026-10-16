"""Explicit publication of one reviewed, sanitized v1 export; never native approval."""

import re
from urllib.parse import urlsplit

from pydantic import Field, StrictBool, field_validator

from dtvp.knowledge.composition import CollectionContext
from dtvp.knowledge.evidence import apply_current_evidence, evidence_ref
from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.legacy_archive import (
    MAX_COMPRESSED,
    ROLES,
    members,
    preview_archive,
    strict_json,
)
from dtvp.knowledge.migration import _base_advisory
from dtvp.knowledge.ownership import current_policy, policy_ref, resolve_ownership
from dtvp.knowledge.service import inventory_sections, validate_time
from dtvp.parsers import parse
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_HEADER = 8192
MAX_RECORDS = 25000
LIMITATIONS = [
    "Only the explicitly reviewed sanitized single-version export is retained; no unsanitized original is claimed preserved.",
    "Exact submitted ZIP and five exported members are readable by current target project readers.",
    "Known credential fields are rejected; this does not prove arbitrary text contains no secrets.",
    "Exported JSON is not verified original pipeline bytes or complete assessment history.",
    "Legacy authors, teams, approvals, suppression and contextual scores are historical unverified claims only; no native decisions or permissions are created.",
    "Only exact source UUID fields or literal UUID-equals-exported-reference mappings admit findings; conflicting or missing mappings stay historical.",
    "Only validated original CVSS 3/4 Base ratings enter source severity; CVSS 2 remains historical, and discovery and source authenticity remain unverified.",
]


def reject_credentials(value):
    """Conservative known-field/user-info rejection, not general secret detection."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                normalized = re.sub(r"[^a-z0-9]", "", key.lower())
                if normalized in {
                    "apikey",
                    "password",
                    "secret",
                    "accesstoken",
                    "authorization",
                    "clientsecret",
                    "dtapikey",
                    "dependencytrackapikey",
                    "apitoken",
                    "refreshtoken",
                    "secretkey",
                } and (child is not None and child != ""):
                    raise ValueError("Reviewed export contains a known credential field")
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            for match in re.finditer(r"[A-Za-z][A-Za-z0-9+.-]{0,63}://[^\s<>\"']+", item):
                try:
                    parsed = urlsplit(match.group())
                    if parsed.username is not None or parsed.password is not None:
                        raise ValueError("Reviewed export contains a credential-bearing URL")
                except ValueError as error:
                    raise ValueError("Reviewed export contains an unsupported URL") from error


class LegacyArchiveMigrationInput(RequestModel):
    request_id: Name
    archive_sha256: Sha
    source_entry_id: Sha
    expected: None
    expected_policy: Sha | None
    expected_evidence: Sha | None
    source: Name
    build_number: int = Field(ge=0, strict=True)
    occurred_at: str
    reason: str = Field(min_length=1, max_length=2000)
    acknowledge_sanitized_export: StrictBool
    acknowledge_operator_review: StrictBool
    acknowledge_project_reader_disclosure: StrictBool

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value):
        return validate_time(value)

    @field_validator("reason")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("A meaningful publication reason is required")
        reject_credentials(value)
        return value

    @field_validator("source")
    @classmethod
    def safe_source(cls, value):
        reject_credentials(value)
        return value

    @field_validator(
        "acknowledge_sanitized_export",
        "acknowledge_operator_review",
        "acknowledge_project_reader_disclosure",
    )
    @classmethod
    def acknowledged(cls, value):
        if value is not True:
            raise ValueError("Explicit acknowledgment is required")
        return value


class LegacyArchiveMigrationApply(LegacyArchiveMigrationInput):
    preview_digest: Sha


def migration_identity(project_id, version, actor_id, data):
    return digest(canonical([project_id, actor_id, data.request_id])), digest(
        canonical(
            [
                "legacy-archive.publication/1",
                project_id,
                version,
                actor_id,
                data.model_dump(mode="json"),
            ]
        )
    )


def migration_receipt(journal, *, project_id, version, actor_id, data):
    with journal.writer():
        return journal.receipt(*migration_identity(project_id, version, actor_id, data))


def _check_raw(raw, data):
    if (
        not isinstance(raw, bytes)
        or len(raw) > MAX_COMPRESSED
        or digest(raw) != data.archive_sha256
    ):
        raise ValueError("Submitted archive digest does not match")


def _candidate(journal, *, project_id, version, actor_id, data, raw):
    _check_raw(raw, data)
    if version.startswith("@"):
        raise ValueError("Publication requires an ordinary product version")
    if journal.resolve(Ref(project_id=project_id, name=version)) is not None:
        raise Conflict("Publication requires a new empty native version")
    archive = preview_archive(raw, limit=100)
    if archive["total"] != 1:
        raise ValueError("Publication requires a reviewed single-version export")
    row = archive["items"][0]
    if row["source_entry_id"] != data.source_entry_id:
        raise ValueError("Selected source entry does not match the exact archive")
    payloads, _ = members(raw)
    manifest = strict_json(payloads["manifest.json"])
    entry = manifest["project"]["versions"][0]
    values = {role: strict_json(payloads[entry["paths"][role]]) for role in ROLES}
    reject_credentials(manifest)
    for value in values.values():
        reject_credentials(value)
    if (
        sum(len(values[role]) for role in ("findings", "vulnerabilities", "assessments"))
        > MAX_RECORDS
    ):
        raise ValueError("Publication source record budget exceeded")
    bom_raw = payloads[entry["paths"]["bom"]]
    document = parse(bom_raw)
    policy_state, config = current_policy(journal, project_id)
    if policy_state != data.expected_policy:
        raise Conflict("Ownership policy changed; prepare publication again")
    sections = {name: {} for name in SECTIONS}
    sections["inventory"], sections["vulnerabilities"] = inventory_sections(
        document,
        artifact_sha=digest(bom_raw),
        source=data.source,
        build_number=data.build_number,
        occurred_at=data.occurred_at,
        collection=CollectionContext(),
        representation="exported_json_member_bytes",
        version=version,
        source_provenance={
            "kind": "reviewed-sanitized-v1-archive",
            "archive_sha256": data.archive_sha256,
            "source_entry_id": data.source_entry_id,
            "claims_verification": "historical_unverified",
        },
    )
    # Native source severity is re-admitted from original Base assertions only.
    sections["vulnerabilities"] = {}
    mapping = {}
    pending = [*values["bom"].get("components", [])]
    metadata = values["bom"].get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Exported BOM metadata must be an object")
    root = metadata.get("component")
    if "component" in metadata and not isinstance(root, dict):
        raise ValueError("Exported BOM root component must be an object")
    if isinstance(root, dict):
        if root.get("components"):
            raise ValueError(
                "Unsupported root-nested composition; exported BOM must expose components at top level"
            )
        pending.append(root)
    native_refs = {item["bom-ref"] for item in document["components"]}
    if isinstance(root, dict) and root.get("bom-ref"):
        native_refs.add(root["bom-ref"])
    seen_refs = set()
    while pending:
        component = pending.pop()
        if not isinstance(component, dict):
            raise ValueError("Exported BOM components must be objects")
        children = component.get("components", [])
        if not isinstance(children, list):
            raise ValueError("Exported BOM component children must be an array")
        reference = component.get("bom-ref")
        if "bom-ref" in component:
            if not isinstance(reference, str) or not reference or reference in seen_refs:
                raise ValueError("Exported BOM references must be unique nonempty text")
            seen_refs.add(reference)
        identity = component.get("uuid")
        if isinstance(identity, str) and identity:
            mapping.setdefault(identity, []).append(component.get("bom-ref"))
        pending.extend(children)
    for reference in native_refs:
        mapping.setdefault(reference, []).append(reference)
    mapping = {
        identity: sorted(set(references), key=lambda value: str(value))
        for identity, references in mapping.items()
    }
    coverage = {
        role: {"exact_source_uuid_refs": 0, "unresolved": 0, "ambiguous": 0}
        for role in ("findings", "assessments")
    }
    counts = {
        "native_source_observations": 0,
        "source_observations_without_original_base": 0,
        "captured_findings": len(values["findings"]),
        "captured_assessments": len(values["assessments"]),
        "captured_vulnerabilities": len(values["vulnerabilities"]),
        "unresolved_source_records": 0,
        "native_assessments": 0,
        "native_reviews": 0,
        "native_scoring_records": 0,
        "inventory_components": len(document["components"]),
    }
    for role in ROLES:
        rows = values[role] if isinstance(values[role], list) else [values[role]]
        for index, record in enumerate(rows):
            sections["history"][f"legacy-v1:{role}:{index}"] = {
                "format": "dtvp.legacy-v1-claim/1",
                "archive_sha256": data.archive_sha256,
                "source_entry_id": data.source_entry_id,
                "channel": role,
                "member_sha256": row["member_pins"][role]["sha256"],
                "claim": record,
                "trust": "historical_unverified",
                "native_approval": False,
            }
            if role not in {"findings", "assessments"}:
                continue
            component = record.get("component", {})
            advisory = record.get("vulnerability", {})
            source_uuid = component.get("uuid") if isinstance(component, dict) else None
            selected = mapping.get(source_uuid, []) if isinstance(source_uuid, str) else []
            identifier = advisory.get("vulnId") if isinstance(advisory, dict) else None
            if len(selected) == 1 and selected[0] in native_refs:
                coverage[role]["exact_source_uuid_refs"] += 1
            else:
                coverage[role]["ambiguous" if len(selected) > 1 else "unresolved"] += 1
            if (
                len(selected) != 1
                or selected[0] not in native_refs
                or not isinstance(identifier, str)
                or not identifier.strip()
            ):
                counts["unresolved_source_records"] += 1
                continue
            ratings = []
            for vector_key, score_key in (
                ("cvssV3Vector", "cvssV3BaseScore"),
                ("cvssV4Vector", "cvssV4Score"),
            ):
                rating = {
                    key: advisory[source]
                    for key, source in (("vector", vector_key), ("score", score_key))
                    if source in advisory
                }
                if rating:
                    ratings.append(rating)
            normalized = _base_advisory(
                {
                    "id": identifier,
                    "description": advisory.get("description", ""),
                    "ratings": ratings,
                }
            )
            if not normalized["ratings"]:
                counts["source_observations_without_original_base"] += 1
            analysis = record.get("analysis")
            if isinstance(analysis, dict):
                normalized["properties"] = [
                    {"name": "dtvp:dt-analysis", "value": canonical(analysis).decode()}
                ]
            sections["vulnerabilities"][f"legacy-v1:{role}:{index}"] = {
                "source": data.source,
                "identifier": identifier,
                "ref": selected[0],
                "advisory": normalized,
                "legacy_archive": {
                    "archive_sha256": data.archive_sha256,
                    "channel": role,
                    "trust": "historical_unverified",
                },
            }
            counts["native_source_observations"] += 1
    for index, claim in enumerate(document["findings"]):
        sections["history"][f"legacy-v1:embedded:{index}"] = {
            "format": "dtvp.legacy-v1-claim/1",
            "archive_sha256": data.archive_sha256,
            "source_entry_id": data.source_entry_id,
            "channel": "embedded-bom",
            "member_sha256": digest(bom_raw),
            "claim": claim,
            "trust": "historical_unverified",
            "native_approval": False,
        }
        if claim["ref"] in native_refs:
            sections["vulnerabilities"][f"legacy-v1:embedded:{index}"] = {
                **claim,
                "source": data.source,
                "advisory": _base_advisory(claim["advisory"]),
            }
            counts["native_source_observations"] += 1
    sections["history"]["legacy-v1:publication"] = {
        "format": "dtvp.legacy-v1-publication/1",
        "archive_sha256": data.archive_sha256,
        "source_entry_id": data.source_entry_id,
        "manifest_sha256": archive["manifest_sha256"],
        "member_pins": row["member_pins"],
        "limitations": LIMITATIONS,
        "declaration": data.model_dump(mode="json", exclude={"preview_digest"}),
    }
    resolve_ownership(sections, version=version, policy_state=policy_state, config=config)
    evidence_state = apply_current_evidence(journal, sections, project_id)
    if evidence_state != data.expected_evidence:
        raise Conflict("Selected evidence changed; prepare publication again")
    losses = set(row["losses"])
    losses.discard("legacy_component_mapping_unresolved_no_name_or_purl_guess")
    if counts["source_observations_without_original_base"]:
        losses.add("original_base_rating_unavailable")
    if any(item["unresolved"] or item["ambiguous"] for item in coverage.values()):
        losses.add("legacy_component_mapping_unresolved_no_name_or_purl_guess")
    report = {
        "format": "dtvp.legacy-archive-migration-preview/1",
        "committed": False,
        "archive_sha256": data.archive_sha256,
        "source_entry_id": data.source_entry_id,
        "target": {
            "project_id": project_id,
            "version": version,
            "source": data.source,
            "build_number": data.build_number,
        },
        "statistics": counts,
        "coverage": coverage,
        "losses": sorted(losses),
        "disclosure": {
            "audience": "project_readers",
            "retains_submitted_sanitized_zip": True,
            "retained_member_count": 5,
        },
        "limitations": LIMITATIONS,
    }
    report["preview_digest"] = digest(
        canonical(
            [report, actor_id, data.model_dump(mode="json", exclude={"preview_digest"}), sections]
        )
    )
    return report, sections, payloads, entry


def preview_migration(journal, **kwargs):
    """Pure rehearsal: no objects, snapshots or references are written."""
    return _candidate(journal, **kwargs)[0]


def apply_migration(journal, *, project_id, version, actor_id, data, raw):
    _check_raw(raw, data)
    receipt = migration_receipt(
        journal, project_id=project_id, version=version, actor_id=actor_id, data=data
    )
    if receipt:
        return receipt
    report, sections, payloads, entry = _candidate(
        journal, project_id=project_id, version=version, actor_id=actor_id, data=data, raw=raw
    )
    if report["preview_digest"] != data.preview_digest:
        raise Conflict("Publication preview does not match the captured inputs")
    artifacts = {journal.objects.put(raw), journal.objects.put(payloads["manifest.json"])}
    artifacts.update(journal.objects.put(payloads[path]) for path in entry["paths"].values())
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason=data.reason,
        sections=sections,
        parents=[sha for sha in (data.expected_policy, data.expected_evidence) if sha],
        artifacts=sorted(artifacts),
    )
    request_id, fingerprint = migration_identity(project_id, version, actor_id, data)
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=Ref(project_id=project_id, name=version), expected=None, target=state)],
        checks=[
            (policy_ref(project_id), data.expected_policy),
            (evidence_ref(project_id), data.expected_evidence),
        ],
    )
