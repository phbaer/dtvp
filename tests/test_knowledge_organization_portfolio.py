"""Global review targets remain distinct from shared decisions and vulnerability IDs."""

import pytest

from dtvp.knowledge.assessments import save_assessment
from dtvp.knowledge.journal import Journal, Ref, Update
from dtvp.knowledge.organization_portfolio import organization_portfolio
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import digest
from tests.test_knowledge_assessments import allow, assessment, save, seed


def two_projects(tmp_path):
    journal = Journal(tmp_path / "journal")
    original = seed(journal)
    second = journal.snapshot(
        project_id="other",
        version="7.1.1",
        actor_id="pipeline",
        reason="Second product",
        sections=load_sections(journal, original),
    )
    journal.publish(
        request_id="other-seed",
        fingerprint=digest(second.encode()),
        updates=[Update(ref=Ref(project_id="other", name="7.1.1"), expected=None, target=second)],
    )
    data = assessment(journal)
    save(journal, data)
    save_assessment(
        journal,
        project_id="other",
        actor_id="analyst",
        assessment_id="decision",
        data=data.model_copy(
            update={"expected_versions": {"7.1.1": second}, "request_id": "other-decision"}
        ),
        submit=True,
        authorize=allow,
    )
    return journal, [{"id": "project", "name": "First"}, {"id": "other", "name": "Second"}]


def test_cross_project_same_logical_names_are_distinct_and_cve_count_is_global(
    tmp_path, monkeypatch
):
    journal, projects = two_projects(tmp_path)
    original = journal.references
    calls = []

    def capture():
        calls.append(True)
        return original()

    monkeypatch.setattr(journal, "references", capture)
    before = journal.head()
    result = organization_portfolio(journal, projects, limit=1)
    counts = result["statistics"]
    assert counts["context_findings"] == 2
    assert counts["unique_vulnerabilities"] == 1
    assert counts["unique_latest_logical_assessments"] == 2
    assert counts["submitted_targets"] == 2 and counts["reviewed_covered_targets"] == 0
    assert counts["required_context_review_workload"]["remaining_targets"] == 2
    assert result["by_team"]["A"] == counts
    assert len(result["items"]) == 1 and result["total"] == 2
    assert calls == [True]
    assert journal.head() == before
    otherpage = organization_portfolio(journal, list(reversed(projects)), offset=1, limit=1)
    assert otherpage["heads_digest"] == result["heads_digest"]
    assert {item["project_id"] for item in result["items"] + otherpage["items"]} == {
        "project",
        "other",
    }


def test_complete_caps_fail_before_workspace_synthesis(tmp_path, monkeypatch):
    from dtvp.knowledge import organization_portfolio as module

    journal, projects = two_projects(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("Must not synthesize an incomplete portfolio")

    monkeypatch.setattr(module, "collect_portfolio", forbidden)
    monkeypatch.setattr(module, "MAX_PROJECTS", 1)
    with pytest.raises(ValueError, match="100 distinct"):
        organization_portfolio(journal, projects)
    monkeypatch.setattr(module, "MAX_PROJECTS", 100)
    monkeypatch.setattr(module, "MAX_VERSIONS", 1)
    with pytest.raises(ValueError, match="1000-version"):
        organization_portfolio(journal, projects)
    monkeypatch.setattr(module, "MAX_VERSIONS", 1000)
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="250000-record"):
        organization_portfolio(journal, projects)


def test_no_projects_and_invalid_filters(tmp_path):
    journal = Journal(tmp_path / "journal")
    result = organization_portfolio(journal, [])
    assert not result["items"] and result["statistics"]["context_findings"] == 0
    with pytest.raises(ValueError, match="lifecycle"):
        organization_portfolio(journal, [], lifecycle="invented")


def test_context_workload_and_object_bytes_fail_before_synthesis(tmp_path, monkeypatch):
    from dtvp.knowledge import organization_portfolio as module

    journal, projects = two_projects(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("Must not synthesize or decode beyond a complete input budget")

    monkeypatch.setattr(module, "collect_portfolio", forbidden)
    monkeypatch.setattr(module, "MAX_TARGETS", 1)
    with pytest.raises(ValueError, match="100000-context-finding"):
        organization_portfolio(journal, projects)
    monkeypatch.setattr(module, "MAX_TARGETS", 100000)
    refs = journal.references()
    monkeypatch.setattr(journal, "references", lambda: refs)
    monkeypatch.setattr(journal, "load", forbidden)
    monkeypatch.setattr(module, "MAX_BYTES", 1)
    with pytest.raises(ValueError, match="64 MiB"):
        organization_portfolio(journal, projects)
