"""Explicit local v2 snapshot rehearsal; historical decisions confer no native authority."""

import json
from collections import Counter
from typing import Literal

from pydantic import Field, field_validator

from dtvp.knowledge.composition import CollectionContext
from dtvp.knowledge.evidence import apply_current_evidence, evidence_ref
from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.ownership import current_policy, policy_ref, resolve_ownership
from dtvp.knowledge.service import inventory_sections, validate_time
from dtvp.parsers import parse
from dtvp.schemas import RequestModel
from dtvp.snapshots import base_rating
from dtvp.storage import canonical, digest

MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024 * 1024
LIMITATIONS = [
    "Only this immutable dtvp.snapshot/1 capture is migrated; this is not complete v2 recovery.",
    "The bundle records all captured decisions but only the latest decision's approval; older approvals may be absent.",
    "Historical metadata, owners, author/reviewer labels, approvals and scores remain unverified historical claims, not native permissions or approvals.",
    "Native composition is parsed from the exact selected original SBOM; the legacy normalized SBOM remains historical evidence only.",
    "Only explicit captured component-ID/ref mappings are used; missing and inactive findings remain archived without identity inference.",
    "Only valid original Base ratings from source observations enter the native queue; missing/unsupported ratings remain unknown and retained in history.",
    "Collection coverage remains unknown unless explicitly declared for the new native baseline; v2 coverage does not establish correctness.",
]


class MigrationInput(RequestModel):
    request_id: Name
    snapshot_id: Name
    snapshot_sha: Sha
    expected: None
    expected_policy: Sha | None
    expected_evidence: Sha | None
    source: Name
    build_number: int = Field(ge=0, strict=True)
    occurred_at: str
    context: CollectionContext = Field(default_factory=CollectionContext)
    acknowledge_historical_claims: Literal[True]

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value):
        return validate_time(value)


class MigrationApply(MigrationInput):
    preview_digest: Sha


def migration_identity(project_id, version, actor_id, data):
    return (
        digest(canonical([project_id, actor_id, data.request_id])),
        digest(
            canonical(
                [
                    "legacy-snapshot.import/1",
                    project_id,
                    version,
                    actor_id,
                    data.model_dump(mode="json"),
                ]
            )
        ),
    )


def migration_receipt(journal, *, project_id, version, actor_id, data):
    """Call only after reauthorizing the current source and target projects."""
    request_id, fingerprint = migration_identity(project_id, version, actor_id, data)
    with journal.writer():
        return journal.receipt(request_id, fingerprint)


def _rows(value, label):
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise ValueError(f"Snapshot {label} must be an array of objects")
    return value


def _base_advisory(advisory):
    if not isinstance(advisory, dict):
        raise ValueError("Snapshot source advisories must be objects")
    ratings = []
    for rating in _rows(advisory.get("ratings", []), "ratings"):
        if isinstance(rating.get("vector"), str) and not isinstance(rating.get("score"), bool):
            valid = base_rating(rating)
            if valid:
                ratings.append(valid)
    # DT documentation is retained as source text; the legacy decoder labels it
    # historical and never creates native human assessment/review records.
    return {
        **{
            key: advisory[key]
            for key in (
                "id",
                "description",
                "cwes",
                "references",
                "aliases",
                "source",
                "properties",
                "analysis",
            )
            if key in advisory
        },
        "ratings": ratings,
    }


def _candidate(
    journal, *, project_id, version, actor_id, data, bundle, source_artifacts, source_proof
):
    if version.startswith("@"):
        raise ValueError("Migration requires an ordinary product version")
    if len(bundle) > MAX_BUNDLE_BYTES or digest(bundle) != data.snapshot_sha:
        raise ValueError("Snapshot bundle digest or supported size does not match")
    payload = json.loads(bundle)
    if not isinstance(payload, dict) or payload.get("schema_version") != "dtvp.snapshot/1":
        raise ValueError("Migration supports dtvp.snapshot/1 JSON only")
    for field in ("project", "release", "coverage", "sbom"):
        if not isinstance(payload.get(field), dict):
            raise ValueError(f"Snapshot {field} must be an object")
    declared = _rows(payload.get("source_revisions"), "source revisions")
    if not declared or not all(isinstance(item.get("sha256"), str) for item in declared):
        raise ValueError("Snapshot source artifact digests must be explicit strings")
    hashes = {item["sha256"] for item in declared}
    if not hashes or None in hashes or set(source_artifacts) != hashes:
        raise ValueError("Every captured source revision requires its exact original bytes")
    if not all(isinstance(raw, bytes) for raw in source_artifacts.values()):
        raise ValueError("Captured original sources must be bytes")
    if sum(len(raw) for raw in source_artifacts.values()) > MAX_SOURCE_BYTES:
        raise ValueError("Captured source artifacts exceed the supported migration size")
    if any(
        not isinstance(raw, bytes) or digest(raw) != sha for sha, raw in source_artifacts.items()
    ):
        raise ValueError("Captured original source artifact digest does not match")
    if payload.get("original_sha256") not in hashes:
        raise ValueError("Selected original SBOM is not a captured source artifact")
    if (
        source_proof.get("snapshot_id") != data.snapshot_id
        or source_proof.get("snapshot_sha") != data.snapshot_sha
    ):
        raise ValueError("Local source proof does not describe this snapshot")
    ref = Ref(project_id=project_id, name=version)
    if journal.resolve(ref) is not None:
        raise Conflict(
            "Migration creates an empty native branch only; existing state is never replaced"
        )
    policy_state, config = current_policy(journal, project_id)
    if policy_state != data.expected_policy:
        raise Conflict("Ownership policy changed; prepare the migration again")
    embedded = parse(canonical(payload["sbom"]))
    raw_sbom = source_artifacts[payload["original_sha256"]]
    document = parse(raw_sbom)
    sections = {name: {} for name in SECTIONS}
    sections["inventory"], sections["vulnerabilities"] = inventory_sections(
        document,
        artifact_sha=digest(raw_sbom),
        source=data.source,
        build_number=data.build_number,
        occurred_at=data.occurred_at,
        collection=data.context,
        representation="original_bytes",
        version=version,
        source_provenance={
            "kind": "local-v2-snapshot-migration",
            "bundle_sha256": data.snapshot_sha,
            "source_proof": source_proof,
            "original_sha256": payload["original_sha256"],
            "claims_verification": "historical_unverified",
        },
    )
    sections["vulnerabilities"] = {}
    refs = {item["bom-ref"] for item in document["components"]}
    root_ref = document["bom"].get("metadata", {}).get("component", {}).get("bom-ref")
    if root_ref:
        refs.add(root_ref)
    components, mappings, mapped_ref_owners = {}, {}, {}
    for item in _rows(payload.get("components"), "components"):
        identity, selected = item.get("id"), item.get("refs")
        if (
            not isinstance(identity, str)
            or identity in components
            or not isinstance(selected, list)
            or not all(isinstance(value, str) for value in selected)
            or len(selected) != len(set(selected))
        ):
            raise ValueError("Snapshot component IDs and explicit ref mappings must be unambiguous")
        for ref in selected:
            if ref in mapped_ref_owners:
                raise ValueError("A captured source ref cannot belong to multiple component IDs")
            mapped_ref_owners[ref] = identity
        components[identity] = item
        mappings[identity] = sorted(set(selected) & refs)
        sections["history"][
            "legacy-component:" + digest(canonical([data.snapshot_sha, identity]))
        ] = {
            "format": "dtvp.legacy-component/1",
            "bundle_sha256": data.snapshot_sha,
            "claim": item,
            "trust": "historical_unverified",
        }
    unresolved, finding_ids, mapped_targets = [], set(), set()
    active_targets, inactive_targets = set(), set()
    counts = {
        "captured_findings": 0,
        "active_findings": 0,
        "mapped_active_findings": 0,
        "native_source_observations": 0,
        "captured_decisions": 0,
        "captured_latest_approvals": 0,
    }
    for finding in _rows(payload.get("findings"), "findings"):
        identity, identifier = finding.get("id"), finding.get("identifier")
        if (
            not isinstance(identity, str)
            or identity in finding_ids
            or not isinstance(identifier, str)
            or not identifier.strip()
        ):
            raise ValueError("Snapshot findings require unique IDs and explicit identifiers")
        finding_ids.add(identity)
        counts["captured_findings"] += 1
        counts["captured_decisions"] += len(_rows(finding.get("decisions", []), "decisions"))
        counts["captured_latest_approvals"] += int(bool(finding.get("approval")))
        selected = mappings.get(finding.get("component_id"), [])
        reasons = []
        if finding.get("active") is not True:
            reasons.append("inactive_finding")
            inactive_targets.update((ref, identifier) for ref in selected)
        else:
            counts["active_findings"] += 1
            if not selected:
                reasons.append("explicit_component_ref_unavailable")
            else:
                counts["mapped_active_findings"] += 1
                active_targets.update((ref, identifier) for ref in selected)
                observations = _rows(finding.get("observations", []), "observations")
                admitted = []
                for observation in observations:
                    advisory = _base_advisory(observation.get("advisory", {}))
                    admitted.append((observation, advisory))
                if not any(advisory["ratings"] for _, advisory in admitted):
                    reasons.append("original_base_rating_unavailable")
                if not admitted:
                    admitted = [
                        (
                            {},
                            {
                                "id": identifier,
                                "description": finding.get("description", ""),
                                "ratings": [],
                            },
                        )
                    ]
                for component_ref in selected:
                    mapped_targets.add((component_ref, identifier))
                    for index, (observation, advisory) in enumerate(admitted):
                        sections["vulnerabilities"][
                            "legacy-source:"
                            + digest(canonical([data.snapshot_sha, identity, component_ref, index]))
                        ] = {
                            "source": "legacy-v2-snapshot",
                            "identifier": identifier,
                            "ref": component_ref,
                            "advisory": advisory,
                            "legacy_snapshot": {
                                "bundle_sha256": data.snapshot_sha,
                                "finding_id": identity,
                                "source_observation_id": observation.get("id"),
                                "source_label": observation.get("source"),
                                "trust": "historical_unverified",
                                "rating_status": "original_base"
                                if advisory["ratings"]
                                else "unknown",
                            },
                        }
                        counts["native_source_observations"] += 1
        if reasons:
            unresolved.append(
                {
                    "finding_id": identity,
                    "identifier": identifier,
                    "component_id": finding.get("component_id"),
                    "reasons": reasons,
                }
            )
        sections["history"][
            "legacy-finding:" + digest(canonical([data.snapshot_sha, identity]))
        ] = {
            "format": "dtvp.legacy-finding/1",
            "bundle_sha256": data.snapshot_sha,
            "mapped_refs": selected,
            "claim": finding,
            "trust": "historical_unverified",
            "native_approval": False,
        }
    counts["selected_original_source_claims"] = len(document["findings"])
    counts["original_inactive_archived"] = 0
    for index, claim in enumerate(document["findings"]):
        sections["history"]["legacy-original:" + digest(canonical([data.snapshot_sha, index]))] = {
            "format": "dtvp.legacy-original-finding/1",
            "bundle_sha256": data.snapshot_sha,
            "claim": claim,
            "trust": "historical_unverified",
        }
        target = claim["ref"], claim["identifier"]
        reasons = []
        if claim["ref"] not in mapped_ref_owners:
            reasons.append("original_source_ref_not_in_captured_component_mapping")
        elif target in inactive_targets and target not in active_targets:
            counts["original_inactive_archived"] += 1
            reasons.append("original_source_claim_inactive")
        else:
            advisory = _base_advisory(claim["advisory"])
            if target not in active_targets:
                reasons.append("original_source_claim_without_captured_active_finding")
            if not advisory["ratings"]:
                reasons.append("original_base_rating_unavailable")
            sections["vulnerabilities"][
                "legacy-original:" + digest(canonical([data.snapshot_sha, index]))
            ] = {
                "source": "legacy-v2-snapshot",
                "identifier": claim["identifier"],
                "ref": claim["ref"],
                "advisory": advisory,
                "legacy_snapshot": {
                    "bundle_sha256": data.snapshot_sha,
                    "channel": "selected-original",
                    "trust": "historical_unverified",
                    "rating_status": "original_base" if advisory["ratings"] else "unknown",
                },
            }
            mapped_targets.add(target)
            counts["native_source_observations"] += 1
        if reasons:
            unresolved.append(
                {
                    "identifier": claim["identifier"],
                    "component_ref": claim["ref"],
                    "channel": "selected-original",
                    "reasons": reasons,
                }
            )
    counts["embedded_source_claims_archived"] = len(embedded["findings"])
    for index, claim in enumerate(embedded["findings"]):
        sections["history"]["legacy-embedded:" + digest(canonical([data.snapshot_sha, index]))] = {
            "format": "dtvp.legacy-embedded-finding/1",
            "bundle_sha256": data.snapshot_sha,
            "claim": claim,
            "trust": "historical_legacy_normalization",
        }
    embedded_edges = {
        (edge["ref"], child)
        for edge in embedded["bom"].get("dependencies", [])
        for child in edge.get("dependsOn", [])
    }
    native_edges = {
        (edge["ref"], child)
        for edge in sections["inventory"]["dependencies"]["edges"]
        for child in edge.get("dependsOn", [])
    }
    sections["history"]["migration:" + data.snapshot_sha] = {
        "format": "dtvp.legacy-snapshot-migration/1",
        "artifact_sha": data.snapshot_sha,
        "source_artifacts": sorted(hashes),
        "source_proof": source_proof,
        "project_claim": payload["project"],
        "release_claim": payload["release"],
        "coverage_claim": payload["coverage"],
        "composition_source": {
            "artifact_sha": payload["original_sha256"],
            "format": document["format"],
            "representation": "original_bytes",
        },
        "component_mappings": mappings,
        "unresolved": unresolved,
        "limitations": LIMITATIONS,
    }
    resolve_ownership(sections, version=version, policy_state=policy_state, config=config)
    evidence_state = apply_current_evidence(journal, sections, project_id)
    if evidence_state != data.expected_evidence:
        raise Conflict("Selected evidence changed; prepare the migration again")
    content = {
        "format": "dtvp.legacy-migration-preview/1",
        "project_id": project_id,
        "version": version,
        "actor_id": actor_id,
        "input": data.model_dump(mode="json", exclude={"preview_digest"}),
        "source_proof": source_proof,
        "sections": sections,
    }
    result = {
        "committed": False,
        "preview_digest": digest(canonical(content)),
        "snapshot_sha": data.snapshot_sha,
        "source_proof": source_proof,
        "composition": {
            "artifact_sha": payload["original_sha256"],
            "format": document["format"],
            "embedded_format": embedded["format"],
            "legacy_derived_edges_not_adopted": len(embedded_edges - native_edges),
            "native_relationship_counts": dict(
                Counter(item["kind"] for item in sections["inventory"]["relationships"]["items"])
            ),
        },
        "captured_coverage": {
            "inventory_claim": payload["coverage"].get("inventory", "unknown"),
            "matching_claim": payload["coverage"].get("matching", "unknown"),
            "excluded_component_total": len(payload["coverage"].get("excluded_components", [])),
            "excluded_components": payload["coverage"].get("excluded_components", [])[:200],
            "source_unresolved_findings_total": len(
                payload["coverage"].get("unresolved_findings", [])
            ),
            "conversion_losses": payload["coverage"].get("conversion_losses", [])[:200],
            "native_normalization_losses": document["losses"],
            "verification": "historical_unverified",
        },
        "target": {
            "project_id": project_id,
            "version": version,
            "source": data.source,
            "build_number": data.build_number,
        },
        "statistics": {
            **counts,
            "inventory_components": len(document["components"]),
            "captured_components": len(components),
            "mapped_source_targets": len(mapped_targets),
            "native_assessments": 0,
            "native_reviews": 0,
            "native_scoring_records": 0,
        },
        "component_mappings": [
            {
                "component_id": identity,
                "declared_refs": components[identity]["refs"],
                "mapped_refs": selected,
                "unresolved_refs": sorted(set(components[identity]["refs"]) - refs),
            }
            for identity, selected in sorted(mappings.items())
        ][:200],
        "component_mappings_total": len(mappings),
        "unresolved": unresolved[:200],
        "unresolved_total": len(unresolved),
        "preview_item_limit": 200,
        "limitations": LIMITATIONS,
    }
    return result, sections, raw_sbom


def preview_migration(journal, **kwargs):
    """Pure: neither content objects nor journal/projection references are written."""
    return _candidate(journal, **kwargs)[0]


def apply_migration(
    journal, *, project_id, version, actor_id, data, bundle, source_artifacts, source_proof
):
    receipt = migration_receipt(
        journal, project_id=project_id, version=version, actor_id=actor_id, data=data
    )
    if receipt:
        return receipt
    result, sections, raw_sbom = _candidate(
        journal,
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        data=data,
        bundle=bundle,
        source_artifacts=source_artifacts,
        source_proof=source_proof,
    )
    if result["preview_digest"] != data.preview_digest:
        raise Conflict("Migration preview does not match the exact captured inputs")
    artifacts = {journal.objects.put(bundle), journal.objects.put(raw_sbom)}
    artifacts.update(journal.objects.put(raw) for raw in source_artifacts.values())
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Explicit local v2 snapshot migration",
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
