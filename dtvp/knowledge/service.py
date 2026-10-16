"""Application operations for the first journal-backed inventory slice."""

from datetime import datetime

from dtvp.knowledge.composition import (
    CollectionContext,
    collection_summary,
    dependency_edges,
    relationships,
)
from dtvp.knowledge.journal import SECTIONS, Conflict, Ref, Update
from dtvp.parsers import parse
from dtvp.storage import canonical, digest


def component_key(ref):
    return "component:" + ("ref:" + ref if len(ref) <= 180 else "sha256:" + digest(ref.encode()))


def part_ref(project_id, version, part_id):
    return Ref(
        kind="source",
        project_id=project_id,
        name="part:" + digest(canonical([version, part_id])),
    )


def inventory_sections(
    document,
    *,
    artifact_sha,
    source,
    build_number,
    occurred_at,
    collection,
    representation,
    version=None,
    part_id=None,
    source_provenance=None,
):
    """Pure coherent-baseline construction shared by intake and explicit migration."""
    relations = relationships(document)
    # Source-local keys remain exact; lineage metadata never rewrites references.
    inventory = {
        "baseline": dict(
            source=source,
            **({"source_provenance": source_provenance} if source_provenance else {}),
            build_number=build_number,
            occurred_at=occurred_at,
            artifact_sha=artifact_sha,
            parser=document["parser"],
            format=document["format"],
            losses=document["losses"],
            representation=representation,
            **({"part_id": part_id, "product_version": version} if part_id else {}),
            **collection_summary(document, collection),
        ),
        **{component_key(c["bom-ref"]): c for c in document["components"]},
        "dependencies": {"edges": dependency_edges(document, relations)},
        "relationships": {"items": relations},
        "root": document["bom"].get("metadata", {}).get("component", {}),
    }
    # Source claims remain separate from future human assessments.
    vulnerabilities = {
        digest(canonical([source, item])): {"source": source, **item}
        for item in document["findings"]
    }
    return inventory, vulnerabilities


def import_inventory(
    journal,
    *,
    project_id,
    version,
    actor_id,
    request_id,
    expected,
    source,
    build_number,
    occurred_at,
    sbom=None,
    raw=None,
    context=None,
    predecessor=None,
    part_id=None,
    source_provenance=None,
    additional_artifacts=(),
):
    """Replace a complete baseline, preserving all other knowledge sections.

    Build numbers are monotonic within one explicitly selected source binding.
    Changing that source needs a future authority-policy operation; this slice
    rejects it instead of silently accepting an incompatible build ordering.
    """
    if (sbom is None) == (raw is None):
        raise ValueError("Provide exactly one SBOM object or original file")
    operation = dict(
        operation="inventory.import/1",
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        expected=expected,
        source=source,
        build_number=build_number,
        occurred_at=occurred_at,
        predecessor=predecessor,
    )
    if raw is None:
        operation["sbom"] = sbom
        raw = canonical(sbom)
        representation = "canonical_json"
    else:
        operation["input_artifact_sha"] = digest(raw)
        representation = "original_bytes"
    # Preserve receipt compatibility for earlier JSON requests without context.
    if context is not None:
        operation["context"] = context
    if part_id is not None:
        operation["part_id"] = part_id
    if source_provenance is not None and not isinstance(source_provenance, dict):
        raise ValueError("Source provenance must be an object")
    if source_provenance:
        operation["source_provenance"] = source_provenance
    if not isinstance(additional_artifacts, (list, tuple, set)) or not all(
        isinstance(sha, str) for sha in additional_artifacts
    ):
        raise ValueError("Additional artifacts must be content identifiers")
    additional_artifacts = sorted(set(additional_artifacts))
    for sha in additional_artifacts:
        try:
            journal.objects.read(sha)
        except (OSError, ValueError) as error:
            raise ValueError("Additional source artifact unavailable or corrupt") from error
    if additional_artifacts:
        operation["additional_artifacts"] = additional_artifacts
    collection = CollectionContext.model_validate(context or {})
    fingerprint = digest(canonical(operation))
    scoped_request = digest(canonical([project_id, actor_id, request_id]))
    # Replay before checking the head: a successful retry may name an old parent.
    with journal.writer():
        receipt = journal.receipt(scoped_request, fingerprint)
    if receipt:
        return receipt
    ref = (
        part_ref(project_id, version, part_id)
        if part_id
        else Ref(project_id=project_id, name=version)
    )
    if journal.resolve(ref) != expected:
        raise Conflict("Branch changed; reload before importing")
    parent = expected or predecessor
    if expected and predecessor:
        raise ValueError("A predecessor is only allowed when creating a version")
    sections = {name: {} for name in SECTIONS}
    if parent:
        previous = journal.state(parent)
        if previous.project_id != project_id:
            raise ValueError("Predecessor must belong to the same product line")
        sections = {
            name: {key: journal.load(sha) for key, sha in journal.records(parent, name).items()}
            for name in SECTIONS
        }
        if part_id and (
            previous.version != version
            or sections["inventory"].get("baseline", {}).get("part_id") != part_id
        ):
            raise Conflict("Constituent predecessor must match its version and part")
        if sections["inventory"].get("baseline", {}).get("kind") == "assembly":
            raise Conflict("An assembly cannot be replaced by a single SBOM import")
        if expected:
            baseline = sections["inventory"]["baseline"]
            if baseline["source"] != source:
                raise Conflict("Changing inventory authority requires an explicit policy")
            before = CollectionContext.model_validate(baseline.get("collection", {}))
            if before.boundary() != collection.boundary():
                raise Conflict(
                    "Different collection scope cannot replace this baseline; "
                    "use an explicit assembly or configuration reconciliation"
                )
            if build_number <= baseline["build_number"]:
                raise Conflict("Build is not newer than the accepted baseline")
    document = parse(raw)
    previous_inventory = sections["inventory"]
    sections["inventory"], sections["vulnerabilities"] = inventory_sections(
        document,
        artifact_sha=journal.objects.put(raw),
        source=source,
        build_number=build_number,
        occurred_at=occurred_at,
        collection=collection,
        representation=representation,
        version=version,
        part_id=part_id,
        source_provenance=source_provenance,
    )
    from dtvp.knowledge.component_lineages import reconcile_lineages

    sections["inventory"]["identity"] = reconcile_lineages(
        previous_inventory,
        sections["inventory"],
        project_id=project_id,
        version=version,
        previous_state=parent,
        previous_version=journal.state(parent).version if parent else None,
        explicit_predecessor=predecessor is not None,
    )
    old_inventory = journal.records(parent, "inventory") if parent else {}
    sections["history"] = {
        **sections["history"],
        **({f"inventory:{parent}": {"state": parent}} if old_inventory else {}),
    }
    # All raw imports referenced by retained history stay reachable via parents.
    policy_state, policy_checks, evidence_state = None, [], None
    if part_id is None:
        from dtvp.knowledge.ownership import current_policy, policy_ref, resolve_ownership

        policy_state, config = current_policy(journal, project_id)
        resolve_ownership(sections, version=version, policy_state=policy_state, config=config)
        policy_checks = [(policy_ref(project_id), policy_state)]
        from dtvp.knowledge.evidence import apply_current_evidence, evidence_ref

        evidence_state = apply_current_evidence(journal, sections, project_id)
        policy_checks.append((evidence_ref(project_id), evidence_state))
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason=f"Import build {build_number}"[:200],
        parents=list(
            dict.fromkeys(
                ([parent] if parent else [])
                + ([policy_state] if policy_state else [])
                + ([evidence_state] if evidence_state else [])
            )
        ),
        sections=sections,
        artifacts=sorted(
            set(journal.state(parent).artifacts if parent else [])
            | {sections["inventory"]["baseline"]["artifact_sha"]}
            | set(additional_artifacts)
        ),
    )
    return journal.publish(
        request_id=scoped_request,
        fingerprint=fingerprint,
        updates=[Update(ref=ref, expected=expected, target=state)],
        checks=policy_checks,
    )


def create_tag(journal, *, project_id, actor_id, name, state, request_id):
    inventory = journal.records(state, "inventory")
    baseline = journal.load(inventory["baseline"]) if "baseline" in inventory else {}
    if not baseline or baseline.get("withdrawn"):
        raise Conflict("Release tags require an accepted product inventory")
    if (
        baseline.get("kind") == "assembly"
        and baseline.get("readiness") != "producer_declared_ready"
    ):
        raise Conflict("Incomplete or unverified assembly cannot be release-tagged")
    if baseline.get("part_id"):
        raise Conflict("A constituent source is not a product release")
    fingerprint = digest(canonical(["tag/1", project_id, actor_id, name, state]))
    return journal.publish(
        request_id=digest(canonical([project_id, actor_id, request_id])),
        fingerprint=fingerprint,
        updates=[
            Update(
                ref=Ref(kind="tag", project_id=project_id, name=name), expected=None, target=state
            )
        ],
    )


def validate_time(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Build observation time must include a timezone")
    return parsed.isoformat()
