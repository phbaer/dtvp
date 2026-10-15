"""Product evidence exists independently, publishes atomically, and never approves."""

import copy
import json

import pytest
from pydantic import ValidationError

from dtvp.knowledge.assessments import load_sections
from dtvp.knowledge.evidence import (
    EvidenceInput,
    WithdrawalInput,
    apply_current_evidence,
    current_evidence,
    evidence_ref,
    import_evidence,
    withdraw_evidence,
)
from dtvp.knowledge.journal import Conflict, Journal, Ref, Update
from dtvp.knowledge.ownership import product_heads
from dtvp.storage import canonical, digest
from tests.test_knowledge_vex import VULN, claims, inventory, openvex


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def heads(journal):
    return product_heads(journal.references(), "project")


def payload(journal, document=None, **changes):
    return EvidenceInput(
        **(
            {
                "request_id": "evidence-1",
                "expected_evidence": current_evidence(journal, "project")[0],
                "expected_versions": heads(journal),
                "source": "supplier",
                "revision": 1,
                "document": document or openvex(),
            }
            | changes
        )
    )


def ingest(journal, data, **changes):
    return import_evidence(journal, project_id="project", actor_id="uploader", data=data, **changes)


def seed(journal, version="7.1.1", apply=True):
    sections = inventory()
    evidence = apply_current_evidence(journal, sections, "project") if apply else None
    documents = current_evidence(journal, "project")[1] if apply else {}
    state = journal.snapshot(
        project_id="project",
        version=version,
        actor_id="pipeline",
        reason="Inventory fixture",
        sections=sections,
        parents=[evidence] if evidence else [],
        artifacts=[record["artifact_sha"] for record in documents.values()],
    )
    journal.publish(
        request_id="branch-" + version,
        fingerprint=digest(version.encode()),
        updates=[Update(ref=Ref(project_id="project", name=version), expected=None, target=state)],
    )
    return state


def current(journal, version="7.1.1"):
    return load_sections(journal, heads(journal)[version])


def withdrawal(journal, sha, **changes):
    return WithdrawalInput(
        **(
            {
                "request_id": "withdraw",
                "expected_evidence": current_evidence(journal, "project")[0],
                "expected_versions": heads(journal),
                "artifact_sha": sha,
                "reason": "The supplier withdrew this claim pending investigation.",
            }
            | changes
        )
    )


def test_evidence_before_sbom_has_dedicated_durable_ref_then_applies_to_future_branch(journal):
    data = payload(journal)
    ingest(journal, data)
    evidence, docs = current_evidence(journal, "project")
    assert heads(journal) == {}
    assert evidence == journal.resolve(evidence_ref("project"))
    assert len(docs) == 1
    record = next(iter(docs.values()))
    assert record["active"] and record["source_revision"] == 1
    assert journal.objects.read(record["artifact_sha"]) == canonical(data.document)
    state = seed(journal)
    assert evidence in journal.state(state).parents
    assert claims(current(journal))[0]["identifier"] == VULN
    assert record["artifact_sha"] in journal.verify_state(state).artifacts


def test_import_reconciles_all_existing_versions_preserving_inventory_and_human_records(journal):
    seed(journal)
    seed(journal, "7.1.2")
    before = {version: current(journal, version) for version in heads(journal)}
    receipt = ingest(journal, payload(journal))
    assert len(receipt[1].updates) == 3
    evidence = current_evidence(journal, "project")[0]
    for version, sections in before.items():
        after = current(journal, version)
        assert after["inventory"] == sections["inventory"]
        assert after["assessments"] == sections["assessments"]
        assert after["reviews"] == sections["reviews"]
        assert claims(after)[0]["trust"] == "unverified"
        assert evidence in journal.state(heads(journal)[version]).parents


def test_explicit_source_ordinal_supersedes_same_binding_not_upload_time(journal):
    seed(journal)
    first = payload(journal, revision=5)
    ingest(journal, first)
    initial = journal.head()
    for revision in (4, 5):
        with pytest.raises(Conflict, match="revision must increase"):
            ingest(
                journal,
                payload(
                    journal,
                    openvex(status="affected"),
                    request_id="old-" + str(revision),
                    revision=revision,
                ),
            )
        assert journal.head() == initial
    revised = openvex(status="affected", action_statement="Upgrade")
    revised["version"] = 2
    revised["timestamp"] = "2020-01-01T00:00:00Z"
    ingest(journal, payload(journal, revised, request_id="revision-6", revision=6))
    _, docs = current_evidence(journal, "project")
    assert len(docs) == 2
    assert sum(record["active"] for record in docs.values()) == 1
    old = docs["evidence-document:" + digest(canonical(first.document))]
    assert old["superseded_by"] == digest(canonical(revised))
    assert claims(current(journal))[0]["advisory"]["normalized_status"] == "affected"
    assert all(
        record["artifact_sha"]
        in journal.verify_state(current_evidence(journal, "project")[0]).artifacts
        for record in docs.values()
    )


def test_independent_claimed_publishers_remain_attributed_without_implicit_trust(journal):
    seed(journal)
    ingest(journal, payload(journal))
    another = openvex(status="affected", action_statement="Upgrade")
    another["author"] = "Other publisher"
    ingest(journal, payload(journal, another, request_id="other-publisher", revision=0))
    assert len(claims(current(journal))) == 2
    assert {item["publisher"] for item in claims(current(journal))} == {
        "Supplier",
        "Other publisher",
    }
    assert all(record["active"] for record in current_evidence(journal, "project")[1].values())


def test_receipt_replay_and_input_conflict_do_not_republish(journal):
    seed(journal)
    data = payload(journal)
    receipt = ingest(journal, data)
    before = journal.head()
    assert ingest(journal, data) == receipt
    assert journal.head() == before
    with pytest.raises(Conflict, match="different input"):
        ingest(journal, data.model_copy(update={"revision": 2}))
    assert journal.head() == before


def test_expected_versions_must_include_all_branches_and_withdrawal_is_atomic(journal):
    seed(journal)
    seed(journal, "7.1.2")
    before = journal.head()
    with pytest.raises(Conflict, match="Product versions changed"):
        ingest(journal, payload(journal, expected_versions={"7.1.1": heads(journal)["7.1.1"]}))
    assert journal.head() == before
    ingest(journal, payload(journal))
    sha = digest(canonical(openvex()))
    data = withdrawal(journal, sha)
    receipt = withdraw_evidence(journal, project_id="project", actor_id="uploader", data=data)
    assert len(receipt[1].updates) == 3
    before = journal.head()
    assert (
        withdraw_evidence(journal, project_id="project", actor_id="uploader", data=data) == receipt
    )
    assert journal.head() == before
    record = current_evidence(journal, "project")[1]["evidence-document:" + sha]
    assert not record["active"]
    assert record["withdrawal"]["reason"] == data.reason
    assert journal.objects.read(sha) == canonical(openvex())
    for version in heads(journal):
        assert not claims(current(journal, version))
        assert current(journal, version)["assessments"] == inventory()["assessments"]


def test_concurrent_branch_creation_prevents_partial_evidence_publication(journal, monkeypatch):
    seed(journal)
    data = payload(journal)
    original_publish = journal.publish
    raced = False

    def racing_publish(**kwargs):
        nonlocal raced
        if not raced:
            raced = True
            monkeypatch.setattr(journal, "publish", original_publish)
            seed(journal, "7.1.2")
        return original_publish(**kwargs)

    monkeypatch.setattr(journal, "publish", racing_publish)
    with pytest.raises(Conflict, match="Product versions changed"):
        ingest(journal, data)
    assert current_evidence(journal, "project") == (None, {})
    assert not claims(current(journal))
    assert not claims(current(journal, "7.1.2"))


def test_byte_exact_input_and_declared_document_must_agree(journal):
    document = openvex()
    raw = json.dumps(document, indent=3).encode() + b"\n"
    data = payload(journal, document)
    ingest(journal, data, raw=raw)
    evidence, docs = current_evidence(journal, "project")
    record = docs["evidence-document:" + digest(raw)]
    assert record["representation"] == "original_bytes"
    assert journal.objects.read(record["artifact_sha"]) == raw
    assert record["artifact_sha"] in journal.verify_state(evidence).artifacts
    before = journal.head()
    different = openvex(status="affected")
    with pytest.raises(ValueError, match="do not match"):
        ingest(journal, payload(journal, different, request_id="mismatch", revision=2), raw=raw)
    assert journal.head() == before


def test_stale_evidence_head_and_noninteger_ordinals_rejected(journal):
    stale = payload(journal)
    ingest(journal, payload(journal))
    before = journal.head()
    with pytest.raises(Conflict, match="evidence changed"):
        ingest(journal, stale.model_copy(update={"request_id": "stale"}))
    assert journal.head() == before
    for invalid in (True, 1.5, "2", -1):
        with pytest.raises(ValidationError):
            payload(journal, revision=invalid)


def test_reapply_replaces_global_document_view_without_touching_baseline_claims(journal):
    ingest(journal, payload(journal))
    sections = inventory()
    sections["vulnerabilities"] = {
        "baseline": {"identifier": VULN, "ref": "one", "source": "pipeline"},
        "evidence-document:stale": {"old": "branch-only"},
    }
    before = copy.deepcopy(sections["inventory"])
    state = apply_current_evidence(journal, sections, "project")
    assert state
    assert "evidence-document:stale" not in sections["vulnerabilities"]
    assert sections["vulnerabilities"]["baseline"]["source"] == "pipeline"
    assert sections["inventory"] == before
    assert len(claims(sections)) == 1


def test_unchanged_document_can_advance_same_source_ordinal_without_duplicate_assertions(journal):
    seed(journal)
    ingest(journal, payload(journal))
    previous = current_evidence(journal, "project")[0]
    ingest(journal, payload(journal, request_id="same-document-new-ordinal", revision=2))
    state, docs = current_evidence(journal, "project")
    assert state != previous
    assert len(docs) == 1
    assert next(iter(docs.values()))["source_revision"] == 2
    assert next(iter(docs.values()))["active"]
    assert len(claims(current(journal))) == 1
    previous_record = next(iter(load_sections(journal, previous)["vulnerabilities"].values()))
    assert previous_record["source_revision"] == 1
    before = journal.head()
    with pytest.raises(Conflict, match="another source binding"):
        ingest(
            journal,
            payload(
                journal,
                request_id="same-bytes-other-binding",
                source="another-supplier",
                revision=3,
            ),
        )
    assert journal.head() == before
