"""Historical assessment visibility, separate from current approval coverage."""

from dtvp.knowledge.comparison import page
from dtvp.knowledge.workspace import load_sections


def retained_assessments(journal, state, *, absent_only=True, team_id=None, offset=0, limit=20):
    revision = journal.verify_state(state)
    sections = load_sections(journal, state)
    contexts = {
        value["id"]: value
        for key, value in sections["ownership"].items()
        if key.startswith("context:")
    }
    claims = {
        (item.get("ref"), item.get("identifier")) for item in sections["vulnerabilities"].values()
    }
    rows = []
    for key, record in sorted(sections["assessments"].items()):
        if not key.startswith("assessment:"):
            continue
        payload = record.get("payload", {})
        targets = [
            item for item in payload.get("targets", []) if item.get("version") == revision.version
        ]
        if team_id:
            targets = [item for item in targets if item.get("team_id") == team_id]
            if not targets:
                continue
        absent = [
            item
            for item in targets
            if item.get("context_id") not in contexts
            or (contexts[item["context_id"]]["component_ref"], item.get("vulnerability_id"))
            not in claims
        ]
        availability = (
            "unknown_scope"
            if not payload.get("targets")
            else "out_of_scope"
            if not targets
            else "absent"
            if absent
            else "present"
        )
        if absent_only and availability != "absent":
            continue
        rows.append(
            {
                "assessment_id": payload.get("assessment_id", key.removeprefix("assessment:")),
                "revision": record.get("revision"),
                "availability": availability,
                "assessment": record,
                "targets": absent if absent_only else targets,
            }
        )
    return {
        "state": state,
        "project_id": revision.project_id,
        "version": revision.version,
        "scope": "recorded_targets_not_current_approval",
        **page(rows, offset, limit),
    }
