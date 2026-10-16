"""Project-wide current-version statistics, pinned once and counted before paging."""

from collections import Counter, defaultdict

from dtvp.knowledge.comparison import product_state
from dtvp.knowledge.filters import scoring_status, severity
from dtvp.knowledge.journal import Ref
from dtvp.knowledge.workspace import LIFECYCLES, load_sections, load_workspace
from dtvp.storage import canonical, digest

FORMAT = "dtvp.portfolio/1"
LIMITATIONS = [
    "Counts describe reported findings in the selected current branches, not verified absence of vulnerabilities or complete software coverage.",
    "Each product version, consuming context and vulnerability is a separate required review target; shared logical decisions are counted separately from that workload.",
    "Team groups can overlap when ownership conflicts; source-coverage and retained-history counts remain unfiltered state-level facts.",
    "Only current published contextual scores contribute contextual severity; proposals and outdated publications do not.",
]


def _logical_id(record):
    return (record or {}).get("payload", {}).get("assessment_id")


def _summary(rows):
    latest, approved = set(), set()
    current_revisions, approved_revisions = set(), set()
    for row in rows:
        coverage = row["coverage"]
        latest_record = coverage.get("assessment")
        approved_record = coverage.get("approved_assessment") if coverage.get("approved") else None
        for record, logical, revisions in (
            (latest_record, latest, current_revisions),
            (approved_record, approved, approved_revisions),
        ):
            if identifier := _logical_id(record):
                logical.add((row.get("project_id"), identifier))
                revisions.add(record["revision"])
    approved_targets = sum(bool(row["coverage"].get("approved")) for row in rows)
    unresolved = sum(row["context"].get("status") != "resolved" for row in rows)
    return {
        "context_findings": len(rows),
        "unique_vulnerabilities": len({row["vulnerability_id"] for row in rows}),
        "unique_latest_logical_assessments": len(latest),
        "unique_latest_assessment_revisions": len(current_revisions),
        "unique_approved_logical_assessments": len(approved),
        "unique_approved_assessment_revisions": len(approved_revisions),
        "recorded_targets": sum(bool(row["coverage"].get("recorded")) for row in rows),
        "submitted_targets": sum(bool(row["coverage"].get("submitted")) for row in rows),
        "reviewed_covered_targets": approved_targets,
        "pending_revision_targets": sum(
            bool(row["coverage"].get("pending_revision")) for row in rows
        ),
        "required_context_review_workload": {
            "required_targets": len(rows),
            "approved_targets": approved_targets,
            "remaining_targets": len(rows) - approved_targets,
            "unresolved_targets": unresolved,
            "not_assessable_targets": sum(
                row["context"].get("status") != "resolved" or not row["coverage"].get("fingerprint")
                for row in rows
            ),
        },
        "by_status": dict(sorted(Counter(row["coverage"]["status"] for row in rows).items())),
        "source_severity": dict(sorted(Counter(row["source_severity"] for row in rows).items())),
        "current_published_severity": dict(
            sorted(
                Counter(
                    severity((row.get("published_score") or {}).get("score"))
                    if scoring_status(row) == "published"
                    else "unknown"
                    for row in rows
                ).items()
            )
        ),
        "scoring_status": dict(sorted(Counter(scoring_status(row) for row in rows).items())),
        "ownership_conflicts": sum(
            len(row["context"].get("candidate_teams", [])) > 1 for row in rows
        ),
        "unassigned_targets": sum(
            not row["context"].get("candidate_teams") and not row["context"].get("team_id")
            for row in rows
        ),
    }


def _state_evidence(journal, state, workspace):
    sections = load_sections(journal, state)
    baseline = sections["inventory"].get("baseline", {})
    collection = baseline.get("collection", {})
    return {
        "scope": "state_unfiltered",
        "baseline_status": "withdrawn" if baseline.get("withdrawn") else "active",
        "collection_coverage": {
            key: collection.get(key, "unknown")
            for key in ("package_coverage", "dependency_coverage", "license_coverage")
        },
        "coverage_verification": baseline.get("coverage_verification", "not_verified"),
        "dependency_graph": baseline.get("dependency_graph", "not_reported"),
        "assembly_readiness": baseline.get("readiness", "not_applicable"),
        "uncontextualized_source_findings": workspace["statistics"][
            "uncontextualized_source_findings"
        ],
        "retained_absent_assessments": workspace["statistics"]["retained_absent_assessments"],
        "retained_unknown_scope_assessments": workspace["statistics"][
            "retained_unknown_scope_assessments"
        ],
    }


def collect_portfolio(
    journal,
    project_id,
    *,
    versions=None,
    team_id=None,
    q="",
    lifecycle="",
    filters=None,
    references=None,
):
    """Callers authorize the project; team filters never grant access.

    One references snapshot fixes the entire selected set before any read-model
    synthesis. No tag, source, configuration or emitted-export ref is a version.
    """
    if lifecycle and lifecycle not in LIFECYCLES:
        raise ValueError("Unknown assessment lifecycle")
    references = journal.references() if references is None else references
    available = {}
    for key, state in references.items():
        ref = Ref.model_validate_json(key)
        if ref.project_id == project_id and ref.kind == "branch":
            try:
                product_state(journal, state, project_id)
            except ValueError:
                continue
            available[ref.name] = state
    selected = set(available) if versions is None else set(versions)
    if selected - available.keys():
        raise ValueError("Unknown requested product version")
    heads = {version: available[version] for version in sorted(selected)}
    rows, by_version, evidence = [], {}, {}
    for version, state in heads.items():
        workspace = load_workspace(
            journal,
            state,
            team_id=team_id,
            q=q,
            lifecycle=lifecycle,
            filters=filters,
            paginate=False,
        )
        local = [{**row, "version": version} for row in workspace["items"]]
        rows.extend(local)
        by_version[version] = _summary(local)
        evidence[version] = _state_evidence(journal, state, workspace)
    teams = defaultdict(list)
    for row in rows:
        context = row["context"]
        candidates = set(context.get("candidate_teams", []))
        if context.get("team_id"):
            candidates.add(context["team_id"])
        for team in sorted(candidates):
            teams[team].append(row)
    result = {
        "format": FORMAT,
        "project_id": project_id,
        "heads": heads,
        "heads_digest": digest(canonical(["dtvp.portfolio-heads/1", project_id, heads])),
        "statistics": _summary(rows),
        "by_version": by_version,
        "by_team": {team: _summary(local) for team, local in sorted(teams.items())},
        "state_evidence": evidence,
        "team_counts_overlap": True,
        "limitations": list(LIMITATIONS),
    }

    return result, rows


def load_portfolio(
    journal, project_id, *, versions=None, team_id=None, q="", lifecycle="", filters=None
):
    result, _ = collect_portfolio(
        journal,
        project_id,
        versions=versions,
        team_id=team_id,
        q=q,
        lifecycle=lifecycle,
        filters=filters,
    )
    return result
