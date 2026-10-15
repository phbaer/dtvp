"""History and semantic deltas are pinned product reads, never identity guesses."""

import copy

import pytest

from dtvp.knowledge.comparison import compare_states, list_product_history, list_product_refs
from dtvp.knowledge.journal import SECTIONS, Journal, Ref, Update
from dtvp.knowledge.scoring import ScoreInput, ScorePublication, prepare_score, publish_score
from dtvp.knowledge.service import create_tag
from dtvp.storage import digest
from tests.test_knowledge_assessments import assessment, current, head, review, save, seed, target
from tests.test_rescoring import BASE, VECTOR


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def compare(journal, before, after, **kwargs):
    return compare_states(journal, "project", before, after, **kwargs)


def test_product_refs_and_history_exclude_nonproduct_refs_and_keep_tagged_past(journal):
    first = seed(journal)
    create_tag(
        journal,
        project_id="project",
        actor_id="manager",
        name="released",
        state=first,
        request_id="release",
    )
    second = seed(journal, parent=first)
    seed(journal, "7.1.2")
    for kind, version in (("policy", "@policy"), ("evidence", "@evidence"), ("source", "7.1.1")):
        sections = {name: {} for name in SECTIONS}
        if kind == "source":
            sections["inventory"]["baseline"] = {"part_id": "container"}
        state = journal.snapshot(
            project_id="project",
            version=version,
            actor_id="pipeline",
            reason="Not a product state",
            sections=sections,
        )
        journal.publish(
            request_id=kind,
            fingerprint=digest(kind.encode()),
            updates=[
                Update(
                    ref=Ref(kind=kind, project_id="project", name=kind), expected=None, target=state
                )
            ],
        )
    refs = list_product_refs(journal, "project")
    assert {(item["kind"], item["name"]) for item in refs["items"]} == {
        ("branch", "7.1.1"),
        ("branch", "7.1.2"),
        ("tag", "released"),
    }
    history = list_product_history(journal, "project", version="7.1.1")
    assert {item["state"] for item in history["items"]} == {first, second}
    assert all(item["version"] == "7.1.1" for item in history["items"])
    page = list_product_history(journal, "project", limit=1)
    assert len(page["items"]) == 1 and page["next_offset"] == 1 and page["total"] == 3


def test_unchanged_nightly_bookkeeping_is_distinct_from_material_changes(journal):
    first = seed(journal)

    def bookkeeping(sections):
        sections["inventory"]["baseline"].update(
            build_number=2, occurred_at="later", artifact_sha="new-raw-sha"
        )
        sections["inventory"]["baseline"]["collection"]["pipeline_run"] = "2"
        sections["inventory"]["component:lib"]["dtvp_origin"]["state"] = "new-source-revision"

    second = seed(journal, parent=first, modify=bookkeeping)
    before = journal.head()
    result = compare(journal, first, second)
    assert result["total"] == 2
    assert all(row["classifications"] == ["bookkeeping"] for row in result["items"])
    assert result["summary"]["by_classification"] == {"bookkeeping": 2}
    assert journal.head() == before
    assert compare(journal, second, second)["total"] == 0


def test_material_component_and_context_delta_has_bounded_rows_and_full_counts(journal):
    first = seed(journal)
    second = seed(
        journal,
        parent=first,
        modify=lambda s: s["inventory"]["component:lib"].update(
            version="2", purl="pkg:generic/lib@2"
        ),
    )
    result = compare(journal, first, second, limit=1)
    assert result["total"] == 2 and len(result["items"]) == 1 and result["next_offset"] == 1
    assert result["summary"]["by_category"] == {"component": 1, "context_finding": 1}
    assert result["summary"]["by_classification"]["material"] == 2
    second_page = compare(journal, first, second, offset=1, limit=1)
    assert second_page["items"][0]["category"] == "context_finding"
    assert (
        second_page["items"][0]["before"]["fingerprint"]
        != second_page["items"][0]["after"]["fingerprint"]
    )
    assert second_page["summary"] == result["summary"]


def test_same_name_and_purl_do_not_reconcile_changed_source_local_refs(journal):
    first = seed(journal)

    def rename_ref(sections):
        item = sections["inventory"].pop("component:lib")
        item["bom-ref"] = "renamed-ref"
        sections["inventory"]["component:renamed-ref"] = item
        for edge in sections["inventory"]["dependencies"]["edges"]:
            edge["ref"] = "renamed-ref" if edge["ref"] == "lib" else edge["ref"]
            edge["dependsOn"] = [
                "renamed-ref" if ref == "lib" else ref for ref in edge["dependsOn"]
            ]
        sections["vulnerabilities"]["claim"]["ref"] = "renamed-ref"

    second = seed(journal, parent=first, modify=rename_ref)
    result = compare(journal, first, second)
    components = [row for row in result["items"] if row["category"] == "component"]
    assert {(row["key"], row["change"]) for row in components} == {
        ("lib", "removed"),
        ("renamed-ref", "added"),
    }
    edges = [row for row in result["items"] if row["category"] == "dependency"]
    assert len(edges) == 2
    assert all("material" in row["classifications"] for row in result["items"])


def test_reassignment_changes_responsibility_without_material_reassessment(journal):
    first = seed(journal)
    save(journal, assessment(journal))
    review(journal)
    approved = head(journal)
    reassigned = seed(journal, parent=approved, team="B")
    result = compare(journal, approved, reassigned)
    assert result["total"] == 1
    assert result["items"][0]["classifications"] == ["ownership"]
    assert (
        result["items"][0]["before"]["status"]
        == result["items"][0]["after"]["status"]
        == "approved"
    )
    assert first != approved


def test_assessment_review_and_scoring_changes_remain_separate_from_original_source(journal):
    def base(sections):
        sections["vulnerabilities"]["claim"]["advisory"]["ratings"] = [
            {"method": "CVSSv31", "vector": BASE, "score": 9.8}
        ]

    first = seed(journal, modify=base)
    save(journal, assessment(journal))
    submitted = head(journal)
    result = compare(journal, first, submitted)
    assert result["items"][0]["classifications"] == ["assessment"]
    review(journal)
    approved = head(journal)
    review_delta = compare(journal, submitted, approved)["items"][0]
    assert "review" in review_delta["classifications"]
    data = ScoreInput(
        request_id="score",
        expected_versions={"7.1.1": approved},
        targets=[target(journal)],
        base_vector=BASE,
        vector=VECTOR,
        rationale="Verified deployment conditions",
    )
    preview, _, _ = prepare_score(journal, project_id="project", data=data)
    assert preview["eligible"]
    publish_score(
        journal,
        project_id="project",
        actor_id="coordinator",
        data=ScorePublication(**data.model_dump(), preview=preview["preview"]),
    )
    scored = head(journal)
    delta = compare(journal, approved, scored)
    assert delta["items"][0]["classifications"] == ["scoring"]
    assert (
        delta["items"][0]["before"]["source_severity"]
        == delta["items"][0]["after"]["source_severity"]
        == "critical"
    )
    assert delta["items"][0]["after"]["published_score"]["current"]


def test_removed_component_keeps_historical_assessment_counts_visible(journal):
    seed(journal)
    save(journal, assessment(journal))
    review(journal)
    approved = head(journal)
    previous = copy.deepcopy(current(journal)["assessments"])

    def remove(sections):
        sections["inventory"].pop("component:lib")
        sections["inventory"]["dependencies"]["edges"] = [{"ref": "app", "dependsOn": []}]
        sections["vulnerabilities"] = {}

    after = seed(journal, parent=approved, modify=remove)
    result = compare(journal, approved, after)
    assert result["retention"]["after"] == {
        "retained_assessments": 1,
        "retained_absent_assessments": 1,
    }
    assert current(journal)["assessments"] == previous
    removed = next(row for row in result["items"] if row["category"] == "context_finding")
    assert removed["before"]["status"] == "approved" and removed["after"] is None


def test_nonproduct_uncommitted_and_crossproduct_states_cannot_be_compared(journal):
    first = seed(journal)
    orphan = journal.snapshot(
        project_id="project",
        version="7.1.1",
        actor_id="actor",
        reason="Unpublished",
        sections=current(journal),
        parents=[first],
    )
    for invalid in (
        orphan,
        journal.snapshot(
            project_id="other",
            version="1",
            actor_id="actor",
            reason="Other",
            sections=current(journal),
        ),
    ):
        with pytest.raises(ValueError, match="committed product history"):
            compare(journal, first, invalid)
    assert list_product_refs(journal, "other")["items"] == []
    for bounds in ({"offset": -1}, {"limit": 0}, {"limit": 201}):
        with pytest.raises(ValueError, match="bounds"):
            compare(journal, first, first, **bounds)
