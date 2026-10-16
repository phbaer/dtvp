"""Read-only CPE policy normalization preview; explicit publication stays in identity API."""

from collections import Counter

from fastapi import APIRouter, HTTPException, Request

from dtvp.api import DB, Auth, project_for
from dtvp.knowledge.cpe import (
    ALGORITHM_VERSION,
    LIMITATIONS,
    DiscoveryInput,
    current_discovery_policy,
    normalize_inputs,
)
from dtvp.storage import canonical, digest

router = APIRouter(prefix="/api/v3")


@router.get("/projects/{project_id}/cpe/editor")
def editor(project_id: str, request: Request, db: DB, actor: Auth):
    project = project_for(db, actor, project_id)
    state, config = current_discovery_policy(request.app.state.knowledge, project_id)
    return {
        "policy_state": state,
        "configuration": config,
        "capabilities": ["configure"] if actor.allowed(db, project, "manage") else [],
        "limitations": LIMITATIONS,
    }


@router.post("/projects/{project_id}/cpe/preview")
def preview(project_id: str, data: DiscoveryInput, request: Request, db: DB, actor: Auth):
    project_for(db, actor, project_id, "manage")
    state, current = current_discovery_policy(request.app.state.knowledge, project_id)
    if state != data.expected:
        raise HTTPException(409, "CPE discovery configuration changed; reload before previewing")
    catalog, rules = normalize_inputs(
        [entry.model_dump() for entry in data.catalog],
        {key: value.model_dump(exclude_none=True) for key, value in data.rules.items()},
    )
    before = Counter(canonical(entry) for entry in current["catalog"])
    after = Counter(canonical(entry) for entry in catalog)
    old_rules = current["rules"]
    content = {
        "format": "dtvp.cpe-policy-preview/1",
        "project_id": project_id,
        "actor_id": actor.user.id,
        "input": data.model_dump(mode="json"),
        "configuration": {
            "algorithm_version": ALGORITHM_VERSION,
            "catalog": catalog,
            "rules": rules,
        },
    }
    return {
        "committed": False,
        "policy_state": state,
        "preview_digest": digest(canonical(content)),
        "configuration": content["configuration"],
        "changes": {
            "catalog_added": sum((after - before).values()),
            "catalog_removed": sum((before - after).values()),
            "rules_added": len(rules.keys() - old_rules.keys()),
            "rules_removed": len(old_rules.keys() - rules.keys()),
            "rules_changed": sum(
                rules[key] != old_rules[key] for key in rules.keys() & old_rules.keys()
            ),
        },
        "limitations": [
            "Preview normalizes supplied policy inputs only; no product state or CPE identity is adopted.",
            "Alias cycles and component-version conflicts are evaluated during candidate discovery.",
            *LIMITATIONS,
        ],
    }
