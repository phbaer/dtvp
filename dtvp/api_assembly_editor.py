"""Guided assembly selection; preview is structural, never a release approval."""

from fastapi import APIRouter, HTTPException, Query, Request

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_intake import intake_parts
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.assembly import (
    AssemblyInput,
    assembly_payload,
    assembly_request_identity,
    build_assembly_candidate,
    publish_assembly,
)
from dtvp.knowledge.comparison import product_state, reachable_states
from dtvp.knowledge.journal import CommitUncertain, Conflict, Name, Ref, Sha
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

router = APIRouter(prefix=API_PREFIX)
LIMITATIONS = [
    "Preview describes the exact selected immutable source parts, structural counts and declared coherence only.",
    "Ownership, external evidence, assessment coverage and final review status are not previewed; publication applies current policy/evidence with CAS.",
    "Part selection never infers component identity or cross-part relationships; only explicit pinned DEPENDS_ON declarations create cross-part dependency edges. CONTAINS remains nondependency evidence; no approval or complete discovery is established.",
]


class ApplyInput(RequestModel):
    assembly: AssemblyInput
    preview_digest: Sha


def preview_candidate(journal, project_id, version, data):
    if version.startswith("@"):
        raise ValueError("Product version names beginning with @ are reserved")
    if data.predecessor:
        if data.predecessor not in reachable_states(journal, project_id):
            raise HTTPException(404, "Assembly predecessor must be committed product history")
        product_state(journal, data.predecessor, project_id)
    candidate = build_assembly_candidate(journal, project_id=project_id, version=version, data=data)
    sections = candidate["sections"]
    inventory = sections["inventory"]
    manifest = inventory["assembly"]
    content = {
        "format": "dtvp.assembly-preview/1",
        "project_id": project_id,
        "version": version,
        "input": assembly_payload(data),
        "previous_kind": candidate["previous_kind"],
        **(
            {"configuration_state": candidate["configuration_state"]}
            if candidate["configuration_state"]
            else {}
        ),
        "selection": [
            {key: part.get(key) for key in ("part_id", "state", "required", "role", "availability")}
            for part in manifest["parts"]
        ],
        "coherence": manifest["coherence"],
        "readiness": manifest["readiness"],
        "missing_required_parts": manifest["missing_required_parts"],
        "selected_part_count": manifest["selected_part_count"],
        "coverage_verification": "not_verified",
        "changes": {
            "removed_parts": manifest["removed_parts"],
            "withdrawn_parts": manifest["withdrawn_parts"],
            "requirements_changed": candidate["changed_requirements"],
        },
        "counts": {
            "component_occurrences": sum(key.startswith("component:") for key in inventory),
            "source_findings": len(sections["vulnerabilities"]),
            "dependency_edges": sum(
                len(edge.get("dependsOn", [])) for edge in inventory["dependencies"]["edges"]
            ),
        },
        **(
            {"relationship_diagnostics": candidate["relationship_diagnostics"]}
            if "relationship_diagnostics" in candidate
            else {}
        ),
    }
    return {**content, "preview_digest": digest(canonical(content)), "limitations": LIMITATIONS}


@router.get("/projects/{project_id}/assembly-target")
def target(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    predecessor: Sha | None = None,
):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    refs = journal.references()
    state = refs.get(Ref(project_id=project_id, name=version).key)
    if state and predecessor:
        raise HTTPException(409, "Predecessor is only allowed when creating a product version")
    parent = state or predecessor
    manifest, kind = None, "none"
    if parent:
        if parent not in reachable_states(journal, project_id, references=refs):
            raise HTTPException(404, "Assembly parent must be committed product history")
        product_state(journal, parent, project_id)
        sections = load_sections(journal, parent)
        manifest = sections["inventory"].get("assembly")
        kind = "assembly" if manifest else "single_baseline"
    parts = [
        {key: part.get(key) for key in ("part_id", "state", "required", "role", "availability")}
        for part in (manifest or {}).get("parts", [])
    ]
    return {
        "project_id": project_id,
        "version": version,
        "state": state,
        "predecessor": predecessor,
        "previous_kind": kind,
        "parts": parts,
        "coherence": (manifest or {}).get("coherence"),
        "capabilities": ["assemble"]
        if actor.allowed(db, project, "write") and not version.startswith("@")
        else [],
        "max_parts": 200,
        **(
            {
                "cross_part_relationships": manifest["cross_part_relationships"],
                "relationship_change_reason": manifest.get("relationship_change_reason", ""),
            }
            if manifest and "cross_part_relationships" in manifest
            else {}
        ),
        "limitations": LIMITATIONS,
    }


@router.get("/projects/{project_id}/assembly-parts")
def parts(
    project_id: str,
    version: Name,
    request: Request,
    db: DB,
    actor: Auth,
    q: str = Query("", max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    return intake_parts(project_id, version, request, db, actor, q, offset, limit)


@router.post("/projects/{project_id}/versions/{version}/assembly-preview")
def preview(
    project_id: str, version: Name, data: AssemblyInput, request: Request, db: DB, actor: Auth
):
    project_for(db, actor, project_id, "write")
    try:
        return preview_candidate(request.app.state.knowledge, project_id, version, data)
    except Conflict as error:
        raise HTTPException(409, str(error)) from error


@router.post("/projects/{project_id}/versions/{version}/assembly-apply", status_code=201)
def apply(project_id: str, version: Name, data: ApplyInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "write")
    journal = request.app.state.knowledge
    try:
        request_id, fingerprint = assembly_request_identity(
            project_id, version, actor.user.id, data.assembly
        )
        with journal.writer():
            receipt = journal.receipt(request_id, fingerprint)
        if not receipt:
            structural = preview_candidate(journal, project_id, version, data.assembly)
            if structural["preview_digest"] != data.preview_digest:
                raise Conflict("Assembly preview differs from exact submitted selection")
            receipt = publish_assembly(
                journal,
                project_id=project_id,
                version=version,
                actor_id=actor.user.id,
                data=data.assembly,
                configuration_guard=structural.get("configuration_state"),
            )
        return projected_response(request, receipt)
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.assembly.request_id)
