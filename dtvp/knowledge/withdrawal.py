"""Withdraw the active single-source selection; never erase historical knowledge."""

from pydantic import Field

from dtvp.knowledge.journal import Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class WithdrawalInput(RequestModel):
    request_id: Name
    expected: Sha
    reason: str = Field(min_length=1, max_length=2000)


def withdraw_inventory(journal, *, project_id, version, actor_id, data):
    if not data.reason.strip():
        raise ValueError("Withdrawal requires a reason")
    fingerprint = digest(
        canonical(["inventory.withdraw/1", project_id, version, actor_id, data.model_dump()])
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    ref = Ref(project_id=project_id, name=version)
    if journal.resolve(ref) != data.expected:
        raise Conflict("Version changed; reload before withdrawing inventory")
    previous = journal.verify_state(data.expected)
    sections = load_sections(journal, data.expected)
    baseline = sections["inventory"].get("baseline", {})
    if not baseline or baseline.get("part_id") or baseline.get("kind") == "assembly":
        raise Conflict(
            "Withdraw single-source product inventories only; assemblies use explicit part selection"
        )
    if baseline.get("withdrawn"):
        raise Conflict("Inventory is already withdrawn")
    sections["history"]["withdrawal:" + data.expected] = {
        "format": "dtvp.inventory-withdrawal/1",
        "state": data.expected,
        "actor_id": actor_id,
        "reason": data.reason,
    }
    sections["inventory"] = {
        "baseline": {
            **baseline,
            "withdrawn": True,
            "withdrawal_reason": data.reason,
            "withdrawn_state": data.expected,
        },
        "dependencies": {"edges": []},
        "relationships": {"items": []},
        "root": {},
    }
    sections["vulnerabilities"] = {}
    from dtvp.knowledge.ownership import current_policy, policy_ref, resolve_ownership

    policy, config = current_policy(journal, project_id)
    resolve_ownership(sections, version=version, policy_state=policy, config=config)
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Withdraw current single-source inventory",
        sections=sections,
        parents=[data.expected],
        artifacts=previous.artifacts,
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=ref, expected=data.expected, target=state)],
        checks=[(policy_ref(project_id), policy)],
    )
