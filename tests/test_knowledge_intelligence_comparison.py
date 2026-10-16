"""Pinned external claims never mutate or reassess historical composition."""

import pytest

from dtvp.knowledge import intelligence_comparison as service
from dtvp.knowledge.evidence import WithdrawalInput, current_evidence, withdraw_evidence
from dtvp.knowledge.intelligence_comparison import IntelligenceInput, compare_intelligence
from dtvp.knowledge.journal import Conflict, CorruptJournal
from tests.test_knowledge_advisory_documents import add, feed, heads, inventory
from tests.test_knowledge_advisory_documents import journal as source_journal

journal = source_journal


def compare(journal, state, evidence=None, **options):
    return compare_intelligence(
        journal,
        "product",
        IntelligenceInput(inventory_state=state, evidence_state=evidence),
        **options,
    )


def test_added_known_id_claims_zero_scores_no_matching_and_readonly(journal, bom):
    initial = inventory(journal, bom)
    document = feed()
    document["advisories"].append(feed("CVE-2099-99999")["advisories"][0])
    add(journal, document)
    evidence = current_evidence(journal, "product")[0]
    before = journal.head(), set(journal.objects.root.rglob("*"))
    result = compare(journal, initial, evidence)
    assert result["statistics"]["nonbaseline_statements"]["after"] == 1
    assert result["total"] == 1 and result["items"][0]["status"] == "added"
    assert result["items"][0]["after"][0]["facts"]["vulnerability"]["ratings"][0]["score"] == 0
    assert result["items"][0]["component_refs"] == ["http"]
    assert result["currentness"]["selected_is_current"]
    assert before == (journal.head(), set(journal.objects.root.rglob("*")))


def test_changed_facts_same_claim_binding_and_identical_refresh(journal, bom):
    inventory(journal, bom)
    add(journal)
    original = heads(journal)["1"]
    add(journal, request_id="same-facts", revision=2)
    same = compare(journal, original, current_evidence(journal, "product")[0])
    assert same["items"][0]["status"] == "unchanged"
    add(journal, feed(score=5), request_id="changed-score", revision=3)
    result = compare(journal, original, current_evidence(journal, "product")[0])
    assert result["items"][0]["status"] == "changed"
    assert result["items"][0]["before"][0]["facts"]["vulnerability"]["ratings"][0]["score"] == 0


def test_inactive_document_and_explicit_null_do_not_assert_provider_retraction(journal, bom):
    inventory(journal, bom)
    add(journal)
    state = heads(journal)["1"]
    evidence, documents = current_evidence(journal, "product")
    artifact = next(iter(documents.values()))["artifact_sha"]
    withdraw_evidence(
        journal,
        project_id="product",
        actor_id="curator",
        data=WithdrawalInput(
            request_id="withdraw",
            expected_evidence=evidence,
            expected_versions=heads(journal),
            artifact_sha=artifact,
            reason="Withdraw this source selection",
        ),
    )
    result = compare(journal, state, current_evidence(journal, "product")[0])
    assert result["items"][0]["status"] == "withdrawn_from_selection"
    assert (
        result["items"][0]["inactive_selected_records"][0]["withdrawal"]["reason"]
        == "Withdraw this source selection"
    )
    assert compare(journal, state)["items"][0]["status"] == "no_longer_selected"


def test_full_digest_pins_pages_and_historical_evidence_survives_live_advancement(journal, bom):
    initial = inventory(journal, bom)
    add(journal)
    selected = current_evidence(journal, "product")[0]
    before = compare(journal, initial, selected, limit=1)
    assert (
        compare(journal, initial, selected, offset=1, limit=1)["report_digest"]
        == before["report_digest"]
    )
    add(journal, feed(score=5), request_id="later", revision=2)
    later = compare_intelligence(
        journal,
        "product",
        IntelligenceInput(
            inventory_state=initial,
            evidence_state=selected,
            expected_digest=before["report_digest"],
        ),
    )
    assert later["report_digest"] == before["report_digest"]
    assert later["items"] == before["items"] and not later["currentness"]["selected_is_current"]
    with pytest.raises(Conflict, match="expected digest"):
        compare_intelligence(
            journal,
            "product",
            IntelligenceInput(
                inventory_state=initial, evidence_state=selected, expected_digest="0" * 64
            ),
        )


def test_unknown_hashes_are_not_decoded_and_uncommitted_states_denied(journal, bom, monkeypatch):
    state = inventory(journal, bom)
    guessed = journal.store({"secret": "arbitrary artifact"})
    original = journal.load

    def guarded(sha, *args):
        if sha == guessed:
            pytest.fail("Guessed hash decoded before committed membership admission")
        return original(sha, *args)

    monkeypatch.setattr(journal, "load", guarded)
    with pytest.raises(KeyError):
        compare(journal, state, guessed)
    with pytest.raises(KeyError):
        compare(journal, guessed)


def test_finite_byte_and_state_budgets_precede_decode_and_corruption_fails_closed(
    journal, bom, monkeypatch
):
    state = inventory(journal, bom)
    monkeypatch.setattr(service, "MAX_BYTES", 1)
    native = journal.load

    def guarded(sha, *args):
        if sha == state:
            pytest.fail("State decoded before byte budget admission")
        return native(sha, *args)

    monkeypatch.setattr(journal, "load", guarded)
    with pytest.raises(ValueError, match="decoded-input budget"):
        compare(journal, state)
    monkeypatch.setattr(service, "MAX_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(service, "MAX_STATES", 0)
    with pytest.raises(ValueError, match="state budget"):
        compare(journal, state)
    monkeypatch.setattr(service, "MAX_STATES", 10000)
    monkeypatch.setattr(journal, "load", native)
    journal.objects.path(state).write_bytes(b"{}")
    with pytest.raises(CorruptJournal):
        compare(journal, state)


def test_vex_excluded_unknown_claims_and_statement_cap_fail_without_truncation(
    journal, bom, monkeypatch
):
    state = inventory(journal, bom)
    add(journal)
    evidence = current_evidence(journal, "product")[0]
    from tests.test_knowledge_vex import openvex

    add(journal, openvex(), request_id="vex", source="supplier")
    evidence = current_evidence(journal, "product")[0]
    report = compare(journal, state, evidence)
    assert sum(report["statistics"]["excluded_document_formats"]["after"].values()) == 1
    assert report["total"] == 1
    monkeypatch.setattr(service, "MAX_CLAIMS", 0)
    with pytest.raises(ValueError, match="statement budget"):
        compare(journal, state, evidence)


def test_conflicting_providers_remain_separate_and_full_counts_precede_paging(journal, bom):
    state = inventory(journal, bom)
    add(journal)
    other = feed(score=8)
    other["publisher"] = "Other attributed provider"
    add(journal, other, request_id="other-provider", source="other-provider")
    selected = current_evidence(journal, "product")[0]
    first = compare(journal, state, selected, limit=1)
    second = compare(journal, state, selected, offset=1, limit=1)
    assert first["total"] == second["total"] == 2
    assert first["statistics"] == second["statistics"]
    assert first["report_digest"] == second["report_digest"]
    assert first["items"][0]["source"] != second["items"][0]["source"]
    assert {
        row["after"][0]["facts"]["vulnerability"]["ratings"][0]["score"]
        for row in first["items"] + second["items"]
    } == {0, 8}


def test_document_budget_refuses_before_loading_selected_document(journal, bom, monkeypatch):
    state = inventory(journal, bom)
    add(journal)
    selected, _ = current_evidence(journal, "product")
    document_sha = next(iter(journal.records(selected, "vulnerabilities").values()))
    native = journal.load

    def guarded(sha, *args):
        if sha == document_sha:
            pytest.fail("Document decoded before complete document-budget admission")
        return native(sha, *args)

    monkeypatch.setattr(journal, "load", guarded)
    monkeypatch.setattr(service, "MAX_DOCUMENTS", 0)
    with pytest.raises(ValueError, match="document budget"):
        compare(journal, state, selected)
