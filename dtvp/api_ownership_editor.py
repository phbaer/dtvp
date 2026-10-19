"""Lossless ownership editing; selector semantics and policy preview remain server-side."""

from collections import Counter
from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from packageurl import PackageURL
from pydantic import Field
from sqlalchemy import select

from dtvp.api import DB, Auth, project_for
from dtvp.api_contract import API_PREFIX
from dtvp.api_knowledge import projected_response, uncertain_response
from dtvp.knowledge.journal import CommitUncertain, Conflict, Sha
from dtvp.knowledge.ownership import (
    OwnershipInput,
    policy_ref,
    product_heads,
    resolve_ownership,
    update_policy,
)
from dtvp.knowledge.selectors import parse_team_mapping_key
from dtvp.knowledge.workspace import load_sections
from dtvp.models import Workspace
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

router = APIRouter(prefix=API_PREFIX)


class SelectorInput(RequestModel):
    mode: Literal["component", "purl", "fallback"] = "component"
    name: str = Field(default="", max_length=200)
    namespace_mode: Literal["exact", "known_empty", "absent_or_unknown"] = "absent_or_unknown"
    namespace: str = Field(default="", max_length=200)
    purl: str = Field(default="", max_length=200)
    case_sensitive: bool = False


class OwnershipApply(OwnershipInput):
    preview_digest: Sha


def _selector_fields(selector):
    return {key: value for key, value in asdict(selector).items() if key != "raw_key"}


def encode_selector(data):
    if data.mode == "fallback":
        if data.case_sensitive:
            raise ValueError("Fallback selectors have no case-sensitive variant")
        raw = "*"
    else:
        modifiers = ["cs"] if data.case_sensitive else []
        if data.mode == "purl":
            value = data.purl.strip()
            PackageURL.from_string(value)
            modifiers.append("purl")
            expected = dict(
                name="",
                group=None,
                purl=value,
                require_no_group=False,
                case_sensitive=data.case_sensitive,
                wildcard=False,
            )
        else:
            name, namespace = data.name.strip(), data.namespace.strip()
            if not name:
                raise ValueError("Component selector requires a name")
            if data.namespace_mode == "exact" and not namespace:
                raise ValueError("Exact namespace requires a nonempty namespace")
            if data.namespace_mode == "known_empty":
                modifiers.append("nogroup")
            value = namespace + ":" + name if data.namespace_mode == "exact" else name
            expected = dict(
                name=name,
                group=namespace if data.namespace_mode == "exact" else None,
                purl=None,
                require_no_group=data.namespace_mode == "known_empty",
                case_sensitive=data.case_sensitive,
                wildcard=False,
            )
        raw = ((",".join(modifiers) + "::") if modifiers else "") + value
        if _selector_fields(parse_team_mapping_key(raw)) != expected:
            raise ValueError(
                "These selector fields cannot be represented unambiguously by v1 syntax; retain the original raw selector"
            )
    if not raw or len(raw) > 200 or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise ValueError("Encoded selector must contain 1 to 200 printable characters")
    return raw


def decode_selector(raw):
    parsed = parse_team_mapping_key(raw)
    fields = SelectorInput(
        mode="fallback" if parsed.wildcard else "purl" if parsed.purl is not None else "component",
        name=parsed.name,
        purl=parsed.purl or "",
        namespace=parsed.group or "",
        namespace_mode="known_empty"
        if parsed.require_no_group
        else "exact"
        if parsed.group is not None
        else "absent_or_unknown",
        case_sensitive=parsed.case_sensitive,
    )
    try:
        canonical_key = encode_selector(fields)
        representable = _selector_fields(parse_team_mapping_key(canonical_key)) == _selector_fields(
            parsed
        )
    except ValueError:
        representable = False
    # Preserve unfamiliar modifier syntax as raw rather than offering a lossy editor.
    if "::" in raw:
        probe = parse_team_mapping_key(raw.split("::", 1)[0] + "::dtvp_selector_probe")
        if probe.name != "dtvp_selector_probe" and probe.purl != "dtvp_selector_probe":
            representable = False
    return {
        "raw": raw,
        "fields": fields.model_dump(),
        "representable": representable,
        "limitations": [
            "Bare names match unknown or known-empty namespaces, not named namespaces.",
            "Known-empty namespace requires reported namespace absence; unknown remains distinct.",
        ],
    }


def _validate_teams(db, data):
    identifiers = {rule.team_id for rule in data.rules}
    actual = set(db.scalars(select(Workspace.id).where(Workspace.id.in_(identifiers))))
    if identifiers - actual:
        raise ValueError("Ownership primary teams must exist in this organization")


def _counts(sections):
    contexts = {
        key: value for key, value in sections["ownership"].items() if key.startswith("context:")
    }
    teams = Counter(
        team for value in contexts.values() for team in value.get("candidate_teams", [])
    )
    return {
        "contexts": len(contexts),
        "by_status": dict(sorted(Counter(value["status"] for value in contexts.values()).items())),
        "by_team": dict(sorted(teams.items())),
    }, contexts


def preview_policy(journal, project_id, data):
    refs = journal.references()
    if (
        refs.get(policy_ref(project_id).key) != data.expected_policy
        or product_heads(refs, project_id) != data.expected_versions
    ):
        raise Conflict("Ownership or product versions changed; reload before preview")
    if set(data.context_roots) - data.expected_versions.keys():
        raise ValueError("Explicit roots must name an existing product version")
    config = data.model_dump(mode="json", include={"rules", "context_roots"})
    versions = {}
    for version, state in sorted(data.expected_versions.items()):
        sections = load_sections(journal, state)
        before, old = _counts(sections)
        resolve_ownership(sections, version=version, config=config)
        after, new = _counts(sections)
        versions[version] = {
            "before": before,
            "after": after,
            "added_contexts": len(new.keys() - old.keys()),
            "removed_contexts": len(old.keys() - new.keys()),
            "changed_contexts": sum(old[key] != new[key] for key in old.keys() & new.keys()),
        }
    content = {
        "format": "dtvp.ownership-editor-preview/1",
        "project_id": project_id,
        "expected_policy": data.expected_policy,
        "expected_versions": data.expected_versions,
        "policy": config,
        "versions": versions,
    }
    return {
        **content,
        "preview_digest": digest(canonical(content)),
        "limitations": [
            "Ownership delegates recursively; explicit child owners shadow ancestors.",
            "Aliases are descriptive labels, not additional required owners or access grants.",
            "Reassignment retains historical assessments and independent review pins; it grants no data access or renewed approvals.",
        ],
    }


@router.get("/projects/{project_id}/ownership/editor")
def editor(project_id: str, request: Request, db: DB, actor: Auth):
    project = project_for(db, actor, project_id)
    journal = request.app.state.knowledge
    refs = journal.references()
    policy = refs.get(policy_ref(project_id).key)
    config = (
        journal.load(journal.records(policy, "ownership")["configuration"])
        if policy
        else {"rules": [], "context_roots": {}}
    )
    can_manage = actor.allowed(db, project, "manage")
    identifiers = {rule["team_id"] for rule in config["rules"]} | set(actor.memberships)
    query = select(Workspace.id, Workspace.name).order_by(Workspace.name, Workspace.id)
    if not can_manage:
        query = query.where(Workspace.id.in_(identifiers))
    teams = [{"id": key, "name": name} for key, name in db.execute(query)]
    return {
        "policy_state": policy,
        "policy": config,
        "versions": product_heads(refs, project_id),
        "selectors": [decode_selector(rule["selector"]) for rule in config["rules"]],
        "capabilities": ["manage"] if can_manage else [],
        "available_teams": teams,
    }


@router.post("/projects/{project_id}/ownership/selectors/encode")
def encode(project_id: str, data: SelectorInput, db: DB, actor: Auth):
    project_for(db, actor, project_id)
    return decode_selector(encode_selector(data))


@router.post("/projects/{project_id}/ownership/editor/preview")
def preview(project_id: str, data: OwnershipInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    _validate_teams(db, data)
    try:
        return preview_policy(request.app.state.knowledge, project_id, data)
    except Conflict as error:
        raise HTTPException(409, str(error)) from error


@router.post("/projects/{project_id}/ownership/editor/apply", status_code=201)
def apply(project_id: str, data: OwnershipApply, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    journal = request.app.state.knowledge
    intake = OwnershipInput.model_validate(data.model_dump(exclude={"preview_digest"}))
    # Match update_policy's exact idempotency identity BEFORE checking stale preview/heads.
    fingerprint = digest(
        canonical(
            ["ownership.configure/1", project_id, actor.user.id, intake.model_dump(mode="json")]
        )
    )
    request_id = digest(canonical([project_id, actor.user.id, intake.request_id]))
    try:
        with journal.writer():
            receipt = journal.receipt(request_id, fingerprint)
        if not receipt:
            _validate_teams(db, intake)
            result = preview_policy(journal, project_id, intake)
            if result["preview_digest"] != data.preview_digest:
                raise Conflict("Ownership preview differs; review the complete policy again")
            receipt = update_policy(
                journal, project_id=project_id, actor_id=actor.user.id, data=intake
            )
    except Conflict as error:
        raise HTTPException(409, str(error)) from error
    except CommitUncertain as error:
        return uncertain_response(error, data.request_id)
    return projected_response(request, receipt)
