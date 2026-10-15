"""Workspace aggregation preserves context, attribution and filtered count scope."""

import pytest

from dtvp.knowledge.journal import SECTIONS, Journal
from dtvp.knowledge.ownership import resolve_ownership
from dtvp.knowledge.workspace import load_sections, load_workspace, source_severity


def source(ref, identifier, score, description, origin="pipeline", **rating):
    return {
        "source": origin,
        "ref": ref,
        "identifier": identifier,
        "advisory": {
            "description": description,
            "ratings": [{"score": score, **rating}],
        },
    }


@pytest.fixture
def workspace(tmp_path):
    journal = Journal(tmp_path / "journal")
    sections = {name: {} for name in SECTIONS}
    sections["inventory"] = {
        "baseline": {"dependency_graph": "reported"},
        "root": {"bom-ref": "aggregate", "name": "Product", "version": "1"},
        **{
            f"component:{ref}": {
                "bom-ref": ref,
                "name": ref,
                "version": "1",
                "group": "acme",
                "purl": f"pkg:generic/acme/{ref}@1",
            }
            for ref in ("app-a", "app-b", "shared", "other")
        },
        "dependencies": {
            "edges": [
                {"ref": "aggregate", "dependsOn": ["app-a", "app-b"]},
                {"ref": "app-a", "dependsOn": ["shared", "other"]},
                {"ref": "app-b", "dependsOn": ["shared"]},
                {"ref": "shared", "dependsOn": []},
                {"ref": "other", "dependsOn": []},
            ]
        },
    }
    sections["vulnerabilities"] = {
        "one": source("shared", "CVE-1", 9.8, "Upstream description", "DT", source={"name": "NVD"}),
        "two": source("shared", "CVE-1", 5.0, "Supplier description", "supplier"),
        "three": source("other", "CVE-2", 4.0, "Different issue", "supplier"),
    }
    resolve_ownership(
        sections,
        version="1",
        config={
            "rules": [
                {"selector": "acme:app-a", "team_id": "A"},
                {"selector": "acme:app-b", "team_id": "B"},
            ],
            "context_roots": {"1": ["app-a", "app-b"]},
        },
    )
    return journal, sections


def snapshot(workspace):
    journal, sections = workspace
    state = journal.snapshot(
        project_id="product", version="1", actor_id="alice", reason="Test", sections=sections
    )
    return journal, state


def test_attributed_claims_coalesce_but_consuming_contexts_do_not(workspace):
    journal, state = snapshot(workspace)
    result = load_workspace(journal, state)
    assert result["project_id"] == "product"
    assert result["version"] == "1"
    shared = [item for item in result["items"] if item["vulnerability_id"] == "CVE-1"]
    assert len(shared) == 2
    assert len({item["id"] for item in shared}) == 2
    assert {item["root"]["name"] for item in shared} == {"app-a", "app-b"}
    for item in shared:
        assert len(item["sourcefacts"]) == 2
        assert len(item["descriptions"]) == 2
        assert {rating["observed_source"] for rating in item["source_ratings"]} == {
            "DT",
            "supplier",
        }
        assert {rating.get("source", {}).get("name") for rating in item["source_ratings"]} == {
            "NVD",
            None,
        }
        assert item["source_severity"] == "critical"
        assert item["published_score"] is None
        assert item["coverage"]["status"] == "unassessed"
        assert item["next_actions"] == ["assess"]
    stats = result["statistics"]
    assert stats["context_findings"] == 3
    assert stats["totals"]["context_findings"] == 3
    assert stats["totals"]["unique_vulnerabilities"] == 2
    assert stats["unique_vulnerabilities"] == 2
    assert stats["by_status"] == {"unassessed": 3}
    assert stats["recorded"] == stats["submitted"] == stats["approved"] == 0
    assert stats["by_team"]["A"]["context_findings"] == 2
    assert stats["by_team"]["B"]["context_findings"] == 1
    assert stats["severity"] == {"critical": 2, "medium": 1}
    assert load_sections(journal, state) == workspace[1]


def test_filter_and_pagination_statistics_cover_full_filtered_result(workspace):
    journal, state = snapshot(workspace)
    page = load_workspace(journal, state, limit=1, q="CVE-1", lifecycle="unassessed")
    assert len(page["items"]) == 1
    assert page["next_offset"] == 1
    assert page["statistics"]["context_findings"] == 2
    following = load_workspace(journal, state, limit=1, q="CVE-1", lifecycle="unassessed", offset=1)
    assert following["statistics"] == page["statistics"]
    assert following["next_offset"] is None
    assert following["items"][0]["id"] != page["items"][0]["id"]
    team = load_workspace(journal, state, team_id="A")
    assert len(team["items"]) == 2
    assert team["statistics"]["context_findings"] == 2
    assert set(team["statistics"]["by_team"]) == {"A"}
    assert (
        load_workspace(journal, state, q="supplier description")["statistics"]["context_findings"]
        == 2
    )
    assert (
        load_workspace(journal, state, lifecycle="approved")["statistics"]["context_findings"] == 0
    )


def test_conflicting_teams_count_explicitly_and_unknown_topology_stays_visible(workspace):
    for context in workspace[1]["ownership"].values():
        if context.get("component_ref") == "shared":
            context.update(
                candidate_teams=["A", "B"],
                team_scope={"A": True, "B": True},
                team_id=None,
                status="topology_unknown",
                dependency_graph="not_reported",
            )
    journal, state = snapshot(workspace)
    result = load_workspace(journal, state)
    assert result["statistics"]["ownership_conflicts"] == 2
    assert result["statistics"]["topology_unknown"] == 2
    assert result["statistics"]["team_counts_overlap"] is True
    assert result["statistics"]["by_team"]["A"]["conflicts"] == 2
    assert result["statistics"]["by_team"]["B"]["conflicts"] == 2
    assert load_workspace(journal, state, team_id="B")["statistics"]["context_findings"] == 2
    assert all(
        item["context"]["dependency_graph"] == "not_reported"
        for item in load_workspace(journal, state, team_id="B")["items"]
    )


def test_unconnected_observations_are_not_invented_contexts(workspace):
    workspace[1]["vulnerabilities"]["absent"] = source("missing", "CVE-3", 10, "Missing component")
    journal, state = snapshot(workspace)
    result = load_workspace(journal, state)
    assert result["statistics"]["uncontextualized_source_findings"] == 1
    assert not any(
        item["component"]["bom-ref"] in {"missing", "aggregate"} for item in result["items"]
    )


@pytest.mark.parametrize(
    "kwargs", [{"limit": 0}, {"limit": 201}, {"offset": -1}, {"lifecycle": "bogus"}]
)
def test_invalid_workspace_queries_fail(workspace, kwargs):
    journal, state = snapshot(workspace)
    with pytest.raises(ValueError):
        load_workspace(journal, state, **kwargs)


@pytest.mark.parametrize(
    ("ratings", "expected"),
    [
        ([{"score": 0}], "none"),
        ([{"score": 3.9}], "low"),
        ([{"score": 7}], "high"),
        ([{"severity": "High"}, {"severity": "critical"}], "critical"),
        ([{"score": 0, "severity": "critical"}], "none"),
        ([], "unknown"),
        ([{"score": True}, {"severity": "unrecognized"}], "unknown"),
    ],
)
def test_source_severity_never_creates_contextual_rescoring(ratings, expected):
    assert source_severity(ratings) == expected


def test_recorded_submitted_and_approved_remain_distinct(workspace):
    from dtvp.knowledge.assessments import Target, target_fingerprint, target_key
    from dtvp.storage import canonical, digest

    journal, sections = workspace
    scopes = [
        (context, finding)
        for context in sections["ownership"].values()
        if context.get("id")
        for finding in sections["vulnerabilities"].values()
        if finding["ref"] == context["component_ref"]
    ]
    unique = {(context["id"], finding["identifier"]): context for context, finding in scopes}
    for index, ((context_id, identifier), context) in enumerate(sorted(unique.items())):
        target = {
            "version": "1",
            "context_id": context_id,
            "vulnerability_id": identifier,
            "team_id": context["team_id"],
            "fingerprint": target_fingerprint(sections, "1", context_id, identifier),
        }
        payload = {
            "assessment_id": str(index),
            "targets": [target],
            "author_id": "analyst",
            "created_at": "2026-10-15T12:00:00Z",
            "state": "affected",
            "rationale": "Evidence",
        }
        revision = digest(canonical(payload))
        sections["assessments"]["assessment:" + str(index)] = {
            "revision": revision,
            "payload": payload,
            "stage": "draft" if index == 0 else "submitted",
        }
        if index == 2:
            key = target_key(
                Target(version="1", context_id=context_id, vulnerability_id=identifier)
            )
            sections["reviews"]["review:" + key] = {
                "status": "approved",
                "target": target,
                "assessment_id": str(index),
                "assessment_revision": revision,
                "assessment": payload,
            }
    journal, state = snapshot(workspace)
    result = load_workspace(journal, state)
    assert result["statistics"]["recorded"] == 3
    assert result["statistics"]["submitted"] == 2
    assert result["statistics"]["approved"] == 1
    assert result["statistics"]["by_status"] == {"draft": 1, "submitted": 1, "approved": 1}
    assert (
        load_workspace(journal, state, lifecycle="submitted")["statistics"]["context_findings"] == 1
    )


def test_removed_assessment_targets_remain_retained_without_current_approval_credit(workspace):
    workspace[1]["assessments"] = {
        "assessment:old": {
            "revision": "a" * 64,
            "payload": {
                "targets": [
                    {"version": "1", "context_id": "b" * 64, "vulnerability_id": "CVE-removed"}
                ]
            },
        },
        "legacy": {"reason": "Legacy unclassified scope"},
    }
    journal, state = snapshot(workspace)
    result = load_workspace(journal, state, q="does-not-match")
    stats = result["statistics"]
    assert stats["context_findings"] == stats["approved"] == 0
    assert stats["retained_assessments"] == 2
    assert stats["retained_absent_assessments"] == 1
    assert stats["retained_unknown_scope_assessments"] == 1
    assert stats["retention_scope"] == "state_unfiltered"
