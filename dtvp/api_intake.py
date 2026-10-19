"""Read-only native file intake targets, including projects without a baseline."""

from fastapi import APIRouter, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.knowledge.composition import CollectionContext
from dtvp.knowledge.journal import Name, Ref
from dtvp.knowledge.service import part_ref

router = APIRouter(prefix=API_PREFIX)


def target(journal, project_id, version, part_id=None):
    ref = (
        part_ref(project_id, version, part_id)
        if part_id
        else Ref(project_id=project_id, name=version)
    )
    state = journal.resolve(ref)
    baseline = {}
    if state:
        revision = journal.verify_state(state)
        if revision.project_id != project_id or revision.version != version:
            raise ValueError("Intake reference has incompatible product/version scope")
        records = journal.records(state, "inventory")
        baseline = journal.load(records["baseline"])
        if baseline.get("part_id") != part_id:
            raise ValueError("Intake source part differs from its reference")
    source = baseline.get("source")
    provenance = baseline.get("source_provenance", {})
    connector = isinstance(source, str) and source.startswith(("dependency-track:", "connector:"))
    connector |= bool(provenance)
    owner = (
        "assembly"
        if baseline.get("kind") == "assembly"
        else "connector"
        if connector
        else "file"
        if state
        else "unassigned"
    )
    reasons = ["reserved_product_version_name"] if version.startswith("@") else []
    if owner == "assembly":
        reasons.append(
            "assembled_product_requires_explicit_part_selection_not_baseline_replacement"
        )
    elif owner == "connector":
        reasons.append(
            "connector_owned_source_requires_explicit_authority_policy_to_replace_with_file"
        )
    return {
        "project_id": project_id,
        "version": version,
        "part_id": part_id,
        "kind": "part" if part_id else "product",
        "state": state,
        "source_authority": owner,
        "blocked_reasons": reasons,
        "scope_template": CollectionContext.model_validate(
            baseline.get("collection") or {}
        ).model_dump(mode="json", include={"subject_kind", "target", "platform", "configuration"})
        if state
        else {},
        "baseline": {
            key: baseline.get(key)
            for key in (
                "source",
                "build_number",
                "occurred_at",
                "collection",
                "format",
                "representation",
                "withdrawn",
            )
        },
    }


@router.get("/projects/{project_id}/intake-target")
def intake_target(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    part_id: Name | None = None,
):
    project = project_for(db, actor, project_id)
    result = target(request.app.state.knowledge, project_id, version, part_id)
    return {
        **result,
        "capabilities": ["import"]
        if actor.allowed(db, project, "write") and not result["blocked_reasons"]
        else [],
        "max_upload_bytes": request.app.state.settings.max_upload_bytes,
        "formats": ["CycloneDX 1.5/1.6 JSON/XML", "SPDX 2.3 JSON"],
        "limitations": [
            "A complete import replaces only this exact source baseline; absence is not remediation.",
            "Source parts do not change the assembled product until explicitly selected.",
            "Declared collection/repository scope is producer input, not verified discovery or build provenance.",
        ],
    }


@router.get("/projects/{project_id}/intake-parts")
def intake_parts(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    q: str = Query("", max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    rows = []
    for key, state in journal.references().items():
        ref = Ref.model_validate_json(key)
        if ref.project_id != project_id or ref.kind != "source" or not ref.name.startswith("part:"):
            continue
        revision = journal.state(state)
        if revision.project_id != project_id:
            raise ValueError("Source part reference belongs to another product")
        if revision.version != version:
            continue
        records = journal.records(state, "inventory")
        baseline = journal.load(records["baseline"]) if "baseline" in records else {}
        part_id = baseline.get("part_id")
        if not part_id or part_ref(project_id, version, part_id).key != key:
            raise ValueError("Source part reference has incompatible identity")
        if q.casefold() in part_id.casefold():
            rows.append(
                {
                    "part_id": part_id,
                    "state": state,
                    "source": baseline.get("source"),
                    "build_number": baseline.get("build_number"),
                }
            )
    rows.sort(key=lambda item: item["part_id"])
    return {
        "items": rows[offset : offset + limit],
        "total": len(rows),
        "next_offset": offset + limit if offset + limit < len(rows) else None,
    }
