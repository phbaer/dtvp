"""Full pinned counts preserve unknowns and independent current versus pending pins."""

from copy import deepcopy

from dtvp.knowledge.pipeline_summary import pipeline_summary
from dtvp.storage import canonical, digest
from tests.test_knowledge_documents import documents, inputs, publish, register, review  # noqa: F401
from tests.test_knowledge_documents import head as document_head
from tests.test_knowledge_workspace import snapshot
from tests.test_knowledge_workspace import workspace as source_workspace

workspace = source_workspace


def test_full_counts_are_deterministic_read_only_and_do_not_infer_clearance(workspace):
    journal, sections = workspace
    sections["inventory"]["baseline"]["format"] = "cyclonedx-json"
    # More than an HTTP page: evidence counters must cover every occurrence.
    for index in range(205):
        sections["inventory"][f"component:extra-{index}"] = {
            "bom-ref": f"extra-{index}",
            "name": f"Extra {index}",
            "licenses": [{"license": {"id": "MIT"}}],
        }
    sections["vulnerabilities"]["unmapped"] = {
        "source": "supplier",
        "ref": "missing",
        "identifier": "CVE-unmapped",
        "advisory": {"ratings": []},
    }
    _, state = snapshot(workspace)
    before = journal.head(), journal.references(), set(journal.objects.root.glob("*/*"))
    result = pipeline_summary(journal, state)
    assert result["vulnerabilities"]["totals"]["context_findings"] == 3
    assert result["vulnerabilities"]["totals"]["unique_vulnerabilities"] == 2
    assert result["vulnerabilities"]["totals"]["approved"] == 0
    assert result["vulnerabilities"]["scoring"] == {"not_published": 3}
    assert result["vulnerabilities"]["uncontextualized_source_finding_keys"] == 1
    assert result["licenses"]["components"] >= 209
    assert result["licenses"]["by_evidence_status"]["reported"] == 205
    assert result["licenses"]["current_approved_components"] == 0
    assert result["inventory"]["producer_declared_coverage"]["package_coverage"] == {"unknown": 1}
    assert result["documents"]["current_approved"] == 0
    assert "ready" not in result and "verdict" not in result
    assert "zero_is_not_clearance" in {row["code"] for row in result["limitations"]}
    expected = deepcopy(result)
    assert expected.pop("summary_digest") == digest(canonical(expected))
    assert pipeline_summary(journal, state) == result
    assert (journal.head(), journal.references(), set(journal.objects.root.glob("*/*"))) == before
    sections["inventory"]["component:shared"]["version"] = "new"
    snapshot(workspace)
    assert pipeline_summary(journal, state) == result


def test_withdrawn_empty_inventory_reports_missing_inputs_and_retained_absence(workspace):
    journal, sections = workspace
    sections["inventory"] = {"baseline": {"withdrawn": True}}
    sections["ownership"] = {}
    sections["assessments"]["old"] = {
        "revision": "a" * 64,
        "payload": {
            "targets": [{"version": "1", "context_id": "absent", "vulnerability_id": "old"}]
        },
    }
    _, state = snapshot(workspace)
    result = pipeline_summary(journal, state)
    assert result["inventory"]["baseline_status"] == "withdrawn"
    assert (
        result["inventory"]["quality_statistics"]["by_code"]["no_inventory_occurrences_reported"]
        == 1
    )
    assert result["retained"]["retained_absent_assessments"] == 1
    assert result["vulnerabilities"]["totals"]["approved"] == 0
    assert result["licenses"]["current_approved_components"] == 0


def test_approved_document_pin_is_independent_of_newer_pending_revision(documents):  # noqa: F811
    journal, _, _ = documents
    register(documents)
    review(documents)
    pinned = document_head(journal)
    approved = pipeline_summary(journal, pinned)
    assert approved["documents"]["current_approved"] == 1
    register(documents, submit=False, raw=b"new pending exact document")
    newer = pipeline_summary(journal, document_head(journal))
    assert newer["documents"]["current_approved"] == 1
    assert newer["documents"]["approved_with_newer_pending_revision"] == 1
    assert pipeline_summary(journal, pinned) == approved


def test_historical_document_approval_is_not_counted_as_current(documents):  # noqa: F811
    from dtvp.knowledge.workspace import load_sections

    journal, _, _ = documents
    register(documents)
    previous = document_head(journal)
    sections = load_sections(journal, previous)
    sections["inventory"]["root"]["version"] = "changed-input"
    publish(journal, previous, sections)
    review(documents, acknowledge_historical=True)
    result = pipeline_summary(journal, document_head(journal))
    assert result["documents"]["by_status"] == {"approved": 1}
    assert result["documents"]["historical_approved"] == 1
    assert result["documents"]["current_approved"] == 0


def test_license_approved_pin_pending_and_stale_are_distinct(tmp_path):
    from dtvp.knowledge.journal import Journal
    from tests.test_knowledge_assessments import head, seed
    from tests.test_knowledge_license_reviews import data, save, status
    from tests.test_knowledge_license_reviews import review as license_review

    journal = Journal(tmp_path / "licenses")
    seed(journal)
    save(journal)
    license_review(journal)
    approved = head(journal)
    old_revision = status(journal)["assessment"]["revision"]
    save(
        journal,
        data(
            journal, request_id="pending", expected_revision=old_revision, disposition="prohibited"
        ),
        submit=False,
    )
    result = pipeline_summary(journal, head(journal))
    assert result["licenses"]["current_approved_components"] == 1
    assert result["licenses"]["approved_with_newer_pending_revision"] == 1
    assert result["licenses"]["retained_by_status"] == {"approved": 1}
    assert (
        pipeline_summary(journal, approved)["licenses"]["approved_with_newer_pending_revision"] == 0
    )
    seed(
        journal,
        parent=head(journal),
        modify=lambda sections: sections["inventory"]["root"].update(version="2"),
    )
    result = pipeline_summary(journal, head(journal))
    assert result["licenses"]["current_approved_components"] == 0
    assert result["licenses"]["retained_by_status"] == {"stale": 1}


def test_pending_assessment_is_not_confused_with_historical_approval(tmp_path):
    from dtvp.knowledge.journal import Journal
    from tests.test_knowledge_assessments import assessment, coverage, head, review, save, seed

    journal = Journal(tmp_path / "assessments")
    seed(journal)
    save(journal, assessment(journal))
    review(journal)
    revision = coverage(journal)["assessment"]["revision"]
    save(
        journal, assessment(journal, request_id="pending", expected_revision=revision), submit=False
    )
    result = pipeline_summary(journal, head(journal))
    assert result["vulnerabilities"]["approved_with_newer_pending_revision"] == 1
    assert result["vulnerabilities"]["totals"]["approved"] == 1
    assert result["vulnerabilities"]["by_team"]["A"]["approved"] == 1
    assert result["vulnerabilities"]["team_counts_overlap"] is True
    seed(
        journal,
        parent=head(journal),
        modify=lambda sections: sections["inventory"]["component:lib"].update(version="2"),
    )
    stale = pipeline_summary(journal, head(journal))
    assert stale["vulnerabilities"]["totals"]["approved"] == 0
    assert stale["vulnerabilities"]["approved_with_newer_pending_revision"] == 0


def test_document_summary_has_no_two_hundred_record_truncation(documents):  # noqa: F811
    from dtvp.knowledge.documents import keys
    from dtvp.knowledge.workspace import load_sections

    journal, _, _ = documents
    register(documents, submit=False)
    previous = document_head(journal)
    sections = load_sections(journal, previous)
    template = sections["history"][keys("architecture")[0]]
    for index in range(201):
        item = deepcopy(template)
        item["payload"]["document_id"] = f"document-{index}"
        item["revision"] = journal.store(item["payload"])
        sections["history"][keys(f"document-{index}")[0]] = item
    state = publish(journal, previous, sections)
    result = pipeline_summary(journal, state)
    assert result["documents"]["recorded"] == 202
    assert result["documents"]["by_status"] == {"draft": 202}
    assert result["documents"]["latest_source_current"] == 202
    assert result["documents"]["current_approved"] == 0
