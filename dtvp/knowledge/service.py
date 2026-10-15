"""Application operations for the first journal-backed inventory slice."""

from datetime import datetime

from dtvp.knowledge.journal import SECTIONS, Conflict, Ref, Update
from dtvp.parsers import parse
from dtvp.storage import canonical, digest


def component_key(ref):
    return "component:" + ("ref:" + ref if len(ref) <= 180 else "sha256:" + digest(ref.encode()))


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
    sbom,
    predecessor=None,
):
    """Replace a complete baseline, preserving all other knowledge sections.

    Build numbers are monotonic within one explicitly selected source binding.
    Changing that source needs a future authority-policy operation; this slice
    rejects it instead of silently accepting an incompatible build ordering.
    """
    operation = dict(
        operation="inventory.import/1",
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        expected=expected,
        source=source,
        build_number=build_number,
        occurred_at=occurred_at,
        sbom=sbom,
        predecessor=predecessor,
    )
    fingerprint = digest(canonical(operation))
    scoped_request = digest(canonical([project_id, actor_id, request_id]))
    # Replay before checking the head: a successful retry may name an old parent.
    with journal.writer():
        receipt = journal.receipt(scoped_request, fingerprint)
    if receipt:
        return receipt
    ref = Ref(project_id=project_id, name=version)
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
        if expected:
            baseline = sections["inventory"]["baseline"]
            if baseline["source"] != source:
                raise Conflict("Changing inventory authority requires an explicit policy")
            if build_number <= baseline["build_number"]:
                raise Conflict("Build is not newer than the accepted baseline")
    raw = canonical(sbom)
    document = parse(raw)
    # Source-local keys are deliberate in the first slice; identity reconciliation
    # and context-aware assessment carryover are not implemented by this importer.
    sections["inventory"] = {
        "baseline": dict(
            source=source,
            build_number=build_number,
            occurred_at=occurred_at,
            artifact_sha=journal.objects.put(raw),
            parser=document["parser"],
            format=document["format"],
            losses=document["losses"],
        ),
        **{component_key(c["bom-ref"]): c for c in document["components"]},
        "dependencies": {"edges": document["bom"].get("dependencies", [])},
        "root": document["bom"].get("metadata", {}).get("component", {}),
    }
    # Source claims remain separate from future human assessments.
    sections["vulnerabilities"] = {
        digest(canonical([source, item])): {"source": source, **item}
        for item in document["findings"]
    }
    old_inventory = journal.records(parent, "inventory") if parent else {}
    sections["history"] = {
        **sections["history"],
        **({f"inventory:{parent}": {"state": parent}} if old_inventory else {}),
    }
    # All raw imports referenced by retained history stay reachable via parents.
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason=f"Import build {build_number}"[:200],
        parents=[parent] if parent else [],
        sections=sections,
        artifacts=[sections["inventory"]["baseline"]["artifact_sha"]],
    )
    return journal.publish(
        request_id=scoped_request,
        fingerprint=fingerprint,
        updates=[Update(ref=ref, expected=expected, target=state)],
    )


def create_tag(journal, *, project_id, actor_id, name, state, request_id):
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
