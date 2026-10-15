"""Deterministic reviewer read models over one immutable knowledge state."""

from collections import Counter

from dtvp.knowledge.journal import SECTIONS
from dtvp.storage import canonical, digest

LIFECYCLES = {
    "approved",
    "submitted",
    "draft",
    "reassessment_needed",
    "unassessed",
    "historically_absent",
}
SEVERITIES = ("unknown", "none", "low", "medium", "high", "critical")


def source_severity(ratings):
    """Prefer the maximum numeric source score; keep every original rating too."""
    scores = [
        item["score"]
        for item in ratings
        if isinstance(item.get("score"), (int, float))
        and not isinstance(item["score"], bool)
        and 0 <= item["score"] <= 10
    ]
    if scores:
        score = max(scores)
        return (
            "critical"
            if score >= 9
            else "high"
            if score >= 7
            else "medium"
            if score >= 4
            else "low"
            if score > 0
            else "none"
        )
    bands = [str(item.get("severity", "unknown")).lower() for item in ratings]
    return max(
        (band for band in bands if band in SEVERITIES), key=SEVERITIES.index, default="unknown"
    )


def _component(value):
    return {key: value.get(key) for key in ("name", "version", "purl", "group", "bom-ref")}


def _statistics(items):
    teams = {}
    for item in items:
        context = item["context"]
        candidates = context.get("candidate_teams", [])
        for team in sorted(
            set(candidates) | ({context["team_id"]} if context.get("team_id") else set())
        ):
            counts = teams.setdefault(
                team,
                {
                    "context_findings": 0,
                    "conflicts": 0,
                    "recorded": 0,
                    "submitted": 0,
                    "approved": 0,
                    "by_status": Counter(),
                },
            )
            counts["context_findings"] += 1
            counts["conflicts"] += int(len(candidates) > 1)
            counts["by_status"][item["coverage"]["status"]] += 1
            for flag in ("recorded", "submitted", "approved"):
                counts[flag] += int(bool(item["coverage"].get(flag)))
    return {
        "context_findings": len(items),
        "unique_vulnerabilities": len({item["vulnerability_id"] for item in items}),
        "by_status": dict(Counter(item["coverage"]["status"] for item in items)),
        "by_team": {
            team: {**counts, "by_status": dict(counts["by_status"])}
            for team, counts in sorted(teams.items())
        },
        "severity": dict(Counter(item["source_severity"] for item in items)),
        "recorded": sum(bool(item["coverage"].get("recorded")) for item in items),
        "submitted": sum(bool(item["coverage"].get("submitted")) for item in items),
        "approved": sum(bool(item["coverage"].get("approved")) for item in items),
        "ownership_conflicts": sum(
            len(item["context"].get("candidate_teams", [])) > 1 for item in items
        ),
        "unassigned": sum(not item["context"].get("candidate_teams") for item in items),
        "topology_unknown": sum(
            item["context"].get("status") == "topology_unknown" for item in items
        ),
        "team_counts_overlap": True,
    }


def load_sections(journal, state):
    return {
        section: {key: journal.load(sha) for key, sha in journal.records(state, section).items()}
        for section in SECTIONS
    }


def load_workspace(
    journal,
    state,
    team_id=None,
    q="",
    lifecycle="",
    offset=0,
    limit=50,
    *,
    context_id=None,
    vulnerability_id=None,
    paginate=True,
):
    """Synthesize attributed claims and contextual coverage; never query providers.

    Team filtering describes responsibility only. Callers enforce authorization.
    Counts describe the entire filtered result before pagination.
    """
    from dtvp.knowledge.assessments import coverage_status
    from dtvp.knowledge.scoring import published_score, review_gate, score_key

    if lifecycle and lifecycle not in LIFECYCLES:
        raise ValueError("Unknown assessment lifecycle")
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid workspace page bounds")
    revision = journal.state(state)
    sections = load_sections(journal, state)
    inventory = sections["inventory"]
    components = {
        item["bom-ref"]: item
        for key, item in inventory.items()
        if key.startswith("component:") and item.get("bom-ref")
    }
    root = inventory.get("root", {})
    if root.get("bom-ref"):
        components.setdefault(root["bom-ref"], root)
    for key, item in inventory.items():
        if key.startswith("part-root:") and item.get("bom-ref"):
            components.setdefault(item["bom-ref"], item)
    claims = {}
    for key, finding in sorted(sections["vulnerabilities"].items()):
        if finding.get("identifier") and finding.get("ref"):
            claims.setdefault((finding["ref"], finding["identifier"]), []).append(
                {"observation_id": key, **finding}
            )
    claims_by_ref = {}
    for (ref, identifier), observations in sorted(claims.items()):
        claims_by_ref.setdefault(ref, []).append((identifier, observations))
    items, represented, active_scopes, score_gates = [], set(), set(), {}
    for key, context in sorted(sections["ownership"].items()):
        if not key.startswith("context:"):
            continue
        ref = context["component_ref"]
        for identifier, observations in claims_by_ref.get(ref, []):
            represented.add((ref, identifier))
            active_scopes.add((context["id"], identifier))
            if (context_id and context["id"] != context_id) or (
                vulnerability_id and identifier != vulnerability_id
            ):
                continue
            if (
                team_id
                and team_id not in context.get("team_scope", {})
                and team_id != context.get("team_id")
            ):
                continue
            coverage = coverage_status(
                journal, sections, revision.version, context["id"], identifier
            )
            ratings = [
                {
                    **rating,
                    "observed_source": observation.get("source"),
                    "observation_id": observation["observation_id"],
                }
                for observation in observations
                for rating in observation.get("advisory", {}).get("ratings", [])
            ]
            descriptions = [
                {
                    "source": observation.get("source"),
                    "observation_id": observation["observation_id"],
                    "text": observation.get("advisory", {}).get("description", ""),
                }
                for observation in observations
                if observation.get("advisory", {}).get("description")
            ]
            gate = None
            if score_key(context["id"], identifier) in sections["scoring"]:
                if identifier not in score_gates:
                    score_gates[identifier] = review_gate(
                        journal, sections, revision.version, identifier
                    )
                gate = score_gates[identifier]
            item = {
                "id": digest(canonical([context["id"], identifier])),
                "context_id": context["id"],
                "vulnerability_id": identifier,
                "component": _component(components.get(ref, {"bom-ref": ref})),
                "root": _component(
                    components.get(context["root_ref"], {"bom-ref": context["root_ref"]})
                ),
                "context": context,
                "sourcefacts": observations,
                "source_ratings": ratings,
                "source_severity": source_severity(ratings),
                "description": descriptions[0]["text"] if descriptions else "",
                "descriptions": descriptions,
                "coverage": coverage,
                "published_score": published_score(
                    journal, sections, revision.version, context["id"], identifier, gate=gate
                ),
                "evidence": [
                    item for item in observations if item.get("kind") == "external-status"
                ],
                "next_actions": {
                    "unassessed": ["assess"],
                    "draft": ["edit", "submit"],
                    "submitted": ["review"],
                    "approved": ["view_review"],
                    "reassessment_needed": ["reassess"],
                    "historically_absent": ["view_history"],
                }.get(coverage["status"], []),
            }
            search = (
                canonical(
                    [
                        item["component"],
                        item["root"],
                        identifier,
                        descriptions,
                        [value.get("source") for value in observations],
                    ]
                )
                .decode()
                .casefold()
            )
            if (not lifecycle or coverage["status"] == lifecycle) and (
                not q or q.casefold() in search
            ):
                items.append(item)
    items.sort(
        key=lambda item: (
            item["vulnerability_id"],
            item["context"]["root_ref"],
            item["context"]["component_ref"],
            item["id"],
        )
    )
    statistics = _statistics(items)
    statistics["totals"] = {
        key: statistics[key]
        for key in (
            "context_findings",
            "unique_vulnerabilities",
            "recorded",
            "submitted",
            "approved",
        )
    }
    # Absent records remain retained knowledge, never current finding approvals.
    statistics["retained_assessments"] = len(sections["assessments"])
    statistics["uncontextualized_source_findings"] = len(claims.keys() - represented)
    absent, unknown = [], 0
    for assessment_id, record in sorted(sections["assessments"].items()):
        targets = record.get("payload", {}).get("targets", [])
        unknown += int(not targets)
        local_targets = [target for target in targets if target.get("version") == revision.version]
        absent_targets = [
            target
            for target in local_targets
            if (target.get("context_id"), target.get("vulnerability_id")) not in active_scopes
        ]
        if absent_targets:
            absent.append(
                {
                    "assessment_id": assessment_id,
                    "revision": record.get("revision"),
                    "targets": absent_targets,
                }
            )
    statistics["retained_absent_assessments"] = len(absent)
    statistics["retained_unknown_scope_assessments"] = unknown
    statistics["retention_scope"] = "state_unfiltered"
    return {
        "state": state,
        "project_id": revision.project_id,
        "version": revision.version,
        "items": items[offset : offset + limit] if paginate else items,
        "next_offset": offset + limit if paginate and offset + limit < len(items) else None,
        "statistics": statistics,
    }
