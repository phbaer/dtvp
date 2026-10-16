"""Complete authorized project selection, captured against one references snapshot."""

from collections import defaultdict

from dtvp.knowledge.journal import SECTIONS, CorruptJournal, Ref, Revision, Section
from dtvp.knowledge.portfolio import LIMITATIONS, _summary, collect_portfolio
from dtvp.knowledge.workspace import LIFECYCLES
from dtvp.storage import canonical, digest

MAX_PROJECTS = 100
MAX_VERSIONS = 1000
MAX_RECORDS = 250_000
MAX_TARGETS = 100_000
MAX_BYTES = 64 * 1024 * 1024


class Budget:
    def __init__(self, journal):
        self.journal, self.seen, self.bytes = journal, set(), 0

    def check(self, sha):
        if sha in self.seen:
            return
        try:
            size = self.journal.objects.path(sha).stat().st_size
        except OSError as error:
            raise CorruptJournal("Missing portfolio object") from error
        if self.bytes + size > MAX_BYTES:
            raise ValueError("Portfolio exceeds the complete 64 MiB input-object budget")
        self.bytes += size
        self.seen.add(sha)

    def load(self, sha):
        self.check(sha)
        return self.journal.load(sha)


def organization_portfolio(
    journal, projects, *, team_id=None, q="", lifecycle="", filters=None, offset=0, limit=25
):
    """Callers must authorize every project; never accept scope from journal names."""
    if lifecycle and lifecycle not in LIFECYCLES:
        raise ValueError("Unknown assessment lifecycle")
    if offset < 0 or not 1 <= limit <= 100:
        raise ValueError("Portfolio pages require nonnegative offset and limit 1..100")
    if len(projects) > MAX_PROJECTS or len({item["id"] for item in projects}) != len(projects):
        raise ValueError("Portfolio requires at most 100 distinct authorized projects")
    refs = journal.references()
    identifiers = {item["id"] for item in projects}
    branches = [
        (ref, state)
        for key, state in refs.items()
        if (ref := Ref.model_validate_json(key)).project_id in identifiers
        and ref.kind == "branch"
        and not ref.name.startswith("@")
    ]
    if len(branches) > MAX_VERSIONS:
        raise ValueError("Portfolio exceeds the complete 1000-version budget")
    # Bound the complete input set before synthesizing any finding rows.
    records, targets, heads = 0, 0, defaultdict(dict)
    budget = Budget(journal)
    for ref, state in branches:
        revision = Revision.model_validate(budget.load(state))
        if (
            revision.project_id != ref.project_id
            or revision.version != ref.name
            or set(revision.sections) != set(SECTIONS)
        ):
            raise ValueError("Portfolio branch identity differs from its pinned complete state")
        heads[ref.project_id][ref.name] = state
        sections = {}
        for section, root in revision.sections.items():
            pointers = Section.model_validate(budget.load(root)).records
            records += len(pointers)
            if records > MAX_RECORDS:
                raise ValueError("Portfolio exceeds the complete 250000-record budget")
            for sha in pointers.values():
                budget.check(sha)
            sections[section] = pointers
        baseline = sections["inventory"].get("baseline")
        if not baseline or budget.load(baseline).get("part_id"):
            raise ValueError("Portfolio branch is not a product inventory state")
        identifiers = defaultdict(set)
        for sha in sections["vulnerabilities"].values():
            claim = budget.load(sha)
            if claim.get("identifier") and claim.get("ref"):
                identifiers[claim["ref"]].add(claim["identifier"])
        for key, sha in sections["ownership"].items():
            if key.startswith("context:"):
                context = budget.load(sha)
                targets += len(identifiers[context["component_ref"]])
                if targets > MAX_TARGETS:
                    raise ValueError("Portfolio exceeds the complete 100000-context-finding budget")
    rows, all_rows = [], []
    for project in sorted(projects, key=lambda item: item["id"]):
        result, local = collect_portfolio(
            journal,
            project["id"],
            versions=list(heads[project["id"]]),
            references=refs,
            team_id=team_id,
            q=q,
            lifecycle=lifecycle,
            filters=filters,
        )
        local = [{**row, "project_id": project["id"]} for row in local]
        all_rows.extend(local)
        rows.append(
            {
                "project_id": project["id"],
                "name": project["name"],
                "heads": result["heads"],
                "statistics": result["statistics"],
                "by_version": result["by_version"],
                "state_evidence": result["state_evidence"],
            }
        )
    teams = defaultdict(list)
    for row in all_rows:
        context = row["context"]
        candidates = set(context.get("candidate_teams", []))
        if context.get("team_id"):
            candidates.add(context["team_id"])
        for team in candidates:
            teams[team].append(row)
    selected_heads = {
        project["id"]: dict(sorted(heads[project["id"]].items())) for project in projects
    }
    return {
        "format": "dtvp.organization-portfolio/1",
        "heads": selected_heads,
        "heads_digest": digest(canonical(["dtvp.organization-portfolio-heads/1", selected_heads])),
        "statistics": _summary(all_rows),
        "by_team": {team: _summary(values) for team, values in sorted(teams.items())},
        "project_count": len(projects),
        "version_count": len(branches),
        "items": rows[offset : offset + limit],
        "total": len(rows),
        "next_offset": offset + limit if offset + limit < len(rows) else None,
        "team_counts_overlap": True,
        "limitations": [
            *LIMITATIONS,
            "Only currently authorized selected projects are counted; this is not an organization completeness claim.",
            "Logical assessment identifiers are scoped to projects; vulnerability identifiers are deduplicated across the full selection.",
            "All statistics precede project paging; source coverage remains unfiltered for each pinned version.",
        ],
    }
