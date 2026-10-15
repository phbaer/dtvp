"""External proposals retain exact native pins without becoming human approvals."""

import copy
from uuid import uuid4

import pytest

from dtvp.knowledge.journal import Conflict, Ref, Update
from dtvp.knowledge.ownership import resolve_ownership
from dtvp.knowledge.proposals import (
    MAX_REPORT_BYTES,
    VScorerProposalInput,
    import_vscorer_proposal,
    list_proposals,
)
from dtvp.knowledge.vscorer import derive_context_inputs
from dtvp.knowledge.workspace import load_sections
from dtvp.rescoring import calculate
from dtvp.storage import canonical, digest
from tests.test_knowledge_vscorer import prepare
from tests.test_knowledge_workspace import workspace as source_workspace
from tests.test_rescoring import BASE, VECTOR

workspace = source_workspace
IDENTIFIER = "CVE-2099-10001"


def bound(workspace):
    journal, state, context = prepare(workspace)
    journal.publish(
        request_id="seed",
        fingerprint=digest(b"seed"),
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=None, target=state)],
    )
    receipt = derive_context_inputs(journal, state, context["id"], "shared", {IDENTIFIER: BASE})[
        "dtvp_source"
    ]
    binding = {
        "receipt": receipt,
        "receipt_sha256": digest(canonical(receipt)),
        "verification": "artifact_scope_and_base_consistency",
        "remote_authenticity": "not_verified",
    }
    fragment = {key: value for key, value in receipt.items() if key != "selected_source_base"} | {
        "selected_source_base": receipt["selected_source_base"],
        "receipt_sha256": binding["receipt_sha256"],
        "verification": binding["verification"],
        "remote_authenticity": "not_verified",
    }
    finding = {
        "id": "external-finding",
        "assessment_id": "external-assessment",
        "cve_id": IDENTIFIER,
        "state": "pending",
        "source_facts": {
            "dtvp_source": fragment,
            "base_vector": BASE,
            "base_score": 9.8,
            "components": [{"bom_ref": "shared"}],
        },
        "preview": {
            "environmental_vector": VECTOR,
            "environmental_score": calculate(BASE, VECTOR)["score"],
            "environmental_approval_allowed": True,
            "approval_blockers": [],
        },
    }
    return (
        journal,
        context,
        VScorerProposalInput(
            request_id="proposal", expected=state, source_binding=binding, finding=finding
        ),
    )


def current(journal):
    return journal.resolve(Ref(project_id="product", name="1"))


def ingest(journal, data):
    return import_vscorer_proposal(
        journal, project_id="product", version="1", actor_id="importer", data=data
    )


def proposals(journal, context):
    return list_proposals(
        journal, load_sections(journal, current(journal)), "1", context["id"], IDENTIFIER
    )


def test_proposal_import_preserves_exact_sources_without_approving_or_publishing(workspace):
    journal, context, data = bound(workspace)
    before = load_sections(journal, data.expected)
    ingest(journal, data)
    state = current(journal)
    after = load_sections(journal, state)
    assert state != data.expected
    for section in ("inventory", "vulnerabilities", "ownership", "assessments", "reviews"):
        assert after[section] == before[section]
    assert not any(key.startswith("score:") for key in after["scoring"])
    proposal = proposals(journal, context)[0]
    assert proposal["provider"] == "vscorer"
    assert proposal["source_receipt"] == data.source_binding["receipt"]
    assert proposal["provider_authenticity"] == "caller_asserted_not_verified"
    assert proposal["verification"] == "dtvp_pinned_inputs_reproduced"
    assert proposal["current"] and proposal["eligible"]
    assert proposal["requires_coordinator_publication"]
    assert proposal["proposal"] == calculate(BASE, VECTOR)
    assert proposal["score_input"] == {
        "targets": [{"version": "1", "context_id": context["id"], "vulnerability_id": IDENTIFIER}],
        "base_vector": BASE,
        "vector": proposal["proposal"]["vector"],
    }
    raw = journal.objects.read(proposal["report_sha256"])
    assert raw == canonical({"source_binding": data.source_binding, "finding": data.finding})
    assert proposal["report_sha256"] in journal.state(state).artifacts
    journal.verify_state(state)


def test_import_retry_replays_receipt_and_stale_expected_head_is_rejected(workspace):
    journal, _, data = bound(workspace)
    result = ingest(journal, data)
    first = journal.head()
    assert ingest(journal, data) == result
    assert journal.head() == first
    with pytest.raises(Conflict):
        ingest(journal, data.model_copy(update={"request_id": "new-request"}))
    assert journal.head() == first


@pytest.mark.parametrize(
    "tamper",
    [
        "artifact",
        "bundle",
        "base",
        "component",
        "fragment",
        "scope",
        "project",
        "state_type",
        "unknown_state",
    ],
)
def test_mismatched_receipt_or_result_rejected_without_publication(workspace, tamper):
    journal, _, data = bound(workspace)
    payload = data.model_dump(mode="json")
    receipt = payload["source_binding"]["receipt"]
    if tamper == "artifact":
        receipt["artifacts"]["cves_sha256"] = "f" * 64
    elif tamper == "bundle":
        receipt["bundle_sha256"] = "f" * 64
    elif tamper == "base":
        receipt["selected_source_base"][IDENTIFIER]["score"] = 1.0
    elif tamper == "component":
        receipt["component_ref"] = "other"
    elif tamper == "fragment":
        payload["finding"]["source_facts"]["dtvp_source"]["state"] = "f" * 64
    elif tamper == "scope":
        payload["finding"]["source_facts"]["components"].append({"bom_ref": "other"})
    elif tamper == "unknown_state":
        receipt["state"] = "e" * 64
    elif tamper == "state_type":
        receipt["state"] = []
    else:
        receipt["project_id"] = "another-product"
    payload["source_binding"]["receipt_sha256"] = digest(canonical(receipt))
    before = journal.head()
    with pytest.raises(ValueError):
        ingest(journal, VScorerProposalInput.model_validate(payload))
    assert journal.head() == before


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("missing", "native_preview_unavailable"),
        ("withheld", "native_preview_withheld"),
        ("score", "native_score_mismatch"),
        ("base", "invalid_contextual_vector"),
    ],
)
def test_bound_but_withheld_or_invalid_candidates_remain_visible_ineligible(
    workspace, change, reason
):
    journal, context, data = bound(workspace)
    finding = copy.deepcopy(data.finding)
    if change == "missing":
        finding.pop("preview")
        finding["speculative_maximum"] = {
            "environmental_vector": VECTOR,
            "environmental_score": 0.0,
        }
    elif change == "withheld":
        finding["preview"]["environmental_approval_allowed"] = False
    elif change == "score":
        finding["preview"]["environmental_score"] = 4.2
    else:
        finding["preview"]["environmental_vector"] = VECTOR.replace("AV:N", "AV:P")
    ingest(journal, data.model_copy(update={"finding": finding}))
    item = proposals(journal, context)[0]
    assert item["current"] and not item["eligible"]
    assert reason in item["ineligibility_reasons"]
    assert item["score_input"] is None
    assert journal.objects.read(item["report_sha256"])


def publish_sections(journal, sections, reason):
    parent = current(journal)
    state = journal.snapshot(
        project_id="product",
        version="1",
        actor_id="pipeline",
        reason=reason,
        sections=sections,
        parents=[parent],
        artifacts=journal.state(parent).artifacts,
    )
    journal.publish(
        request_id=str(uuid4()),
        fingerprint=digest(state.encode()),
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=parent, target=state)],
    )


def test_source_changes_make_retained_proposal_stale_but_assignment_alone_does_not(workspace):
    journal, context, data = bound(workspace)
    ingest(journal, data)
    sections = load_sections(journal, current(journal))
    resolve_ownership(
        sections,
        version="1",
        config={
            "rules": [{"selector": "*", "team_id": "new-team"}],
            "context_roots": {"1": ["app-a", "app-b"]},
        },
    )
    publish_sections(journal, sections, "Reassign")
    assert proposals(journal, context)[0]["eligible"]
    sections = load_sections(journal, current(journal))
    sections["vulnerabilities"]["one"]["advisory"]["description"] = "Changed material advisory"
    publish_sections(journal, sections, "Changed advisory")
    stale = proposals(journal, context)[0]
    assert not stale["eligible"] and not stale["current"]
    assert "source_evidence_changed" in stale["ineligibility_reasons"]
    assert stale["source_receipt"]["state"] == data.expected
    sections["vulnerabilities"] = {}
    publish_sections(journal, sections, "Remove vulnerabilities")
    assert "source_target_absent" in proposals(journal, context)[0]["ineligibility_reasons"]


def test_old_source_can_be_imported_as_stale_evidence_without_approval(workspace):
    journal, context, data = bound(workspace)
    sections = load_sections(journal, current(journal))
    sections["vulnerabilities"]["one"]["advisory"]["description"] = "New advisory"
    publish_sections(journal, sections, "New source")
    ingest(journal, data.model_copy(update={"expected": current(journal)}))
    assert not proposals(journal, context)[0]["eligible"]
    assert proposals(journal, context)[0]["source_receipt"]["state"] == data.expected


def test_proposal_source_label_is_attributed_and_report_size_is_bounded(workspace):
    journal, context, data = bound(workspace)
    ingest(journal, data.model_copy(update={"source_label": "VScorer isolated deployment"}))
    assert proposals(journal, context)[0]["source_label"] == "VScorer isolated deployment"
    oversized = copy.deepcopy(data.finding)
    oversized["extra_report"] = "x" * MAX_REPORT_BYTES
    with pytest.raises(ValueError, match="8 MiB"):
        ingest(
            journal,
            data.model_copy(
                update={
                    "expected": current(journal),
                    "finding": oversized,
                    "request_id": "oversized",
                }
            ),
        )
