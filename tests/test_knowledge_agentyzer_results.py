"""Returned source-analysis reports never become human decisions or source claims."""

import copy

import pytest

from dtvp.knowledge.agentyzer_results import (
    AgentyzerResultInput,
    import_agentyzer_result,
    list_agentyzer_results,
)
from dtvp.knowledge.journal import Conflict, Ref
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical
from tests.test_knowledge_agentyzer import COMMIT, VERSION, derive, imported, qualified
from tests.test_knowledge_agentyzer import journal as source_journal

journal = source_journal
BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VECTOR = BASE + "/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:N/MA:N"


def report(derived):
    return {
        "format": "dtvp.agentyzer-result-envelope/1",
        "job": {
            "job_id": "job-1",
            "status": "completed",
            "request": copy.deepcopy(derived["request"]),
            "llm_provider": "claimed-provider",
            "model": "claimed-model",
        },
        "report": {
            "source_input": {
                "binding": "verified_git_commit",
                "requested_commit": COMMIT,
                "resolved_commit": COMMIT,
                "artifact_verified": False,
            },
            "assessment": {
                "application_eligible": True,
                "rescoring_eligible": True,
                "affected": True,
                "analysis": "EXPLOITABLE",
                "confidence": "High",
                "verdict": "Affected",
                "summary": "Synthetic reachable dependency",
                "reasoning": "Manifests and call sites support review.",
                "code_coverage": {"permits_exclusion": False},
                "version_analysis": {
                    "detected_version": "1.2.0",
                    "comparison_inputs": {"component_name": "demo-http"},
                },
                "adjusted_cvss": {
                    "original_vector": BASE,
                    "original_score": 9.8,
                    "adjusted_vector": VECTOR,
                    "adjusted_score": 0.0,
                    "version": "3.1",
                },
            },
            "steps": [
                {"step": "scan_dependencies", "findings": {"found": True}, "evidence": ["uv.lock"]}
            ],
        },
    }


@pytest.fixture
def inputs(journal, bom):
    state = imported(journal, bom, context=qualified())
    derived = derive(journal, state)
    return state, derived


def data(state, derived, raw=None, **changes):
    return AgentyzerResultInput(
        request_id="result-1",
        expected=state,
        input_receipt=derived["receipt"],
        raw_report=raw if raw is not None else report(derived),
        **changes,
    )


def execute(journal, value, actor="security"):
    receipt = import_agentyzer_result(
        journal, project_id="product", version=VERSION, actor_id=actor, data=value
    )
    state = receipt[1].updates[0].target
    sections = load_sections(journal, state)
    source = value.input_receipt
    rows = list_agentyzer_results(
        journal, sections, VERSION, source.context_id, source.vulnerability_id
    )
    return receipt, state, sections, rows


def test_bound_native_report_retains_raw_evidence_and_separate_proposals(journal, inputs):
    state, derived = inputs
    before = load_sections(journal, state)
    _, after, sections, rows = execute(journal, data(state, derived))
    assert after != state
    for section in ("inventory", "ownership", "vulnerabilities", "assessments", "reviews"):
        assert sections[section] == before[section]
    assert len(rows) == 1
    item = rows[0]
    assert item["current"] and item["application_eligible"] and item["rescoring_eligible"]
    assert item["proposal_state"] == "affected"
    assert item["proposal"]["score"] == 0
    assert item["score_input"]["vector"] == VECTOR
    assert item["provider_authenticity"] == "caller_asserted_not_verified"
    assert item["source_proof"]["source_binding"]["status"] == "receipt_consistent"
    assert item["source_proof"]["source_commit_consistent"] is True
    assert item["build_binding_verified"] is False
    assert item["binary_binding_verified"] is False
    assert journal.objects.read(item["report_sha256"]) == canonical(report(derived))
    assert "proposal:" + item["id"] in sections["scoring"]
    assert all(not key.startswith("published:") for key in sections["scoring"])


@pytest.mark.parametrize(
    "mutation",
    [
        "vulnerability",
        "repository",
        "project_versions",
        "scope",
        "commit",
        "requested_commit",
        "resolved_commit",
        "binding",
        "package",
        "package_version",
        "missing_commit",
        "bare",
    ],
)
def test_cross_scope_or_partial_reports_are_retained_but_ineligible(journal, inputs, mutation):
    state, derived = inputs
    raw = report(derived)
    if mutation in {"vulnerability", "repository", "project_versions", "scope", "commit"}:
        key = {
            "vulnerability": "vuln_id",
            "repository": "component_name",
            "scope": "assessment_scope",
            "commit": "source_commit",
        }.get(mutation, mutation)
        raw["job"]["request"][key] = ["other"] if mutation == "project_versions" else "wrong"
    elif mutation in {"requested_commit", "resolved_commit", "binding"}:
        raw["report"]["source_input"][mutation] = "wrong"
    elif mutation == "missing_commit":
        raw["report"]["source_input"].pop("resolved_commit")
    elif mutation == "package":
        raw["report"]["assessment"]["version_analysis"]["comparison_inputs"]["component_name"] = (
            "gateway"
        )
    elif mutation == "package_version":
        raw["report"]["assessment"]["version_analysis"]["detected_version"] = VERSION
    else:
        raw = raw["report"]
    _, _, _, rows = execute(journal, data(state, derived, raw))
    assert not rows[0]["application_eligible"]
    assert not rows[0]["rescoring_eligible"]
    assert rows[0]["ineligibility_reasons"]
    assert rows[0]["score_input"] is None
    assert journal.objects.read(rows[0]["report_sha256"]) == canonical(raw)


@pytest.mark.parametrize(
    "path",
    [
        "assessment",
        "source_input",
        "version_analysis",
        "comparison_inputs",
        "code_coverage",
        "adjusted_cvss",
        "steps",
        "analysis",
    ],
)
def test_malformed_nested_containers_never_crash_or_gain_eligibility(journal, inputs, path):
    state, derived = inputs
    raw = report(derived)
    value = raw["report"]
    if path in {"assessment", "source_input", "steps"}:
        value[path] = "wrong-container"
    elif path == "comparison_inputs":
        value["assessment"]["version_analysis"][path] = ["wrong"]
    else:
        value["assessment"][path] = ["wrong"]
        if path == "analysis":
            value["assessment"]["affected"] = False
            value["assessment"]["code_coverage"]["permits_exclusion"] = True
    _, _, _, rows = execute(journal, data(state, derived, raw))
    assert not rows[0]["application_eligible"]
    assert rows[0]["ineligibility_reasons"]


@pytest.mark.parametrize(
    "mutation", ["base", "math", "missing", "missing_original_score", "provider", "conflict"]
)
def test_scoring_requires_actual_native_vectors_math_and_pinned_original_base(
    journal, inputs, mutation
):
    state, derived = inputs
    raw = report(derived)
    assessment = raw["report"]["assessment"]
    if mutation == "base":
        assessment["adjusted_cvss"]["adjusted_vector"] = VECTOR.replace("AV:N", "AV:P", 1)
    elif mutation == "math":
        assessment["adjusted_cvss"]["adjusted_score"] = 9.8
    elif mutation == "missing":
        assessment.pop("adjusted_cvss")
    elif mutation == "missing_original_score":
        assessment["adjusted_cvss"].pop("original_score")
    elif mutation == "provider":
        assessment["rescoring_eligible"] = False
    else:
        assessment["cvss_score"] = 4.1
    _, _, _, rows = execute(journal, data(state, derived, raw))
    assert rows[0]["application_eligible"]
    assert not rows[0]["rescoring_eligible"]
    assert rows[0]["score_input"] is None


def test_receipt_tampering_is_rejected_before_publication(journal, inputs):
    state, derived = inputs
    value = data(state, derived)
    value.input_receipt.subject_digest = "sha256:" + "b" * 64
    before = journal.head()
    with pytest.raises(ValueError, match="receipt differs"):
        execute(journal, value)
    assert journal.head() == before


def test_idempotency_and_explicit_expected_head(journal, inputs):
    state, derived = inputs
    value = data(state, derived)
    first, after, _, _ = execute(journal, value)
    assert execute(journal, value)[0] == first
    with pytest.raises(Conflict):
        execute(journal, value.model_copy(update={"request_id": "other-request"}))
    assert journal.resolve(Ref(project_id="product", name=VERSION)) == after


def test_current_and_stale_are_derived_without_dropping_history(journal, inputs):
    state, derived = inputs
    _, _, sections, rows = execute(journal, data(state, derived))
    source = data(state, derived).input_receipt
    next(
        value
        for key, value in sections["inventory"].items()
        if key.startswith("component:") and value.get("bom-ref") == "http"
    )["version"] = "2.0.0"
    stale = list_agentyzer_results(
        journal, sections, VERSION, source.context_id, source.vulnerability_id
    )
    assert not stale[0]["current"] and not stale[0]["application_eligible"]
    assert "source_evidence_changed" in stale[0]["ineligibility_reasons"]
    assert stale[0]["report_sha256"] == rows[0]["report_sha256"]
    sections["ownership"].pop("context:" + source.context_id)
    absent = list_agentyzer_results(
        journal, sections, VERSION, source.context_id, source.vulnerability_id
    )
    assert "source_target_absent" in absent[0]["ineligibility_reasons"]


def test_distinct_import_actors_and_requests_do_not_replace_prior_attribution(journal, inputs):
    state, derived = inputs
    _, after, _, original = execute(journal, data(state, derived))
    newer = data(after, derived).model_copy(update={"request_id": "second-result"})
    _, _, _, rows = execute(journal, newer, actor="other-importer")
    assert len(rows) == 2
    assert {row["imported_by"] for row in rows} == {"security", "other-importer"}
    assert original[0]["id"] in {row["id"] for row in rows}


def test_unqualified_input_receipt_stays_ineligible_without_inventing_commit(journal, bom):
    state = imported(journal, bom, context={})
    derived = derive(journal, state)
    _, _, _, rows = execute(journal, data(state, derived))
    assert not rows[0]["application_eligible"]
    assert rows[0]["source_proof"]["source_binding"]["expected_commit"] is None
    assert rows[0]["source_proof"]["source_commit_consistent"] is False


def test_raw_json_size_and_depth_limits_fail_before_publication(journal, inputs):
    state, derived = inputs
    before = journal.head()
    with pytest.raises(ValueError, match="8 MiB"):
        execute(journal, data(state, derived, {"large": "x" * (8 * 1024 * 1024)}))
    nested = {}
    for _ in range(66):
        nested = {"child": nested}
    with pytest.raises(ValueError, match="nesting/node"):
        execute(journal, data(state, derived, nested))
    assert journal.head() == before


def test_namespaced_package_requires_qualified_report_identity(journal, bom):
    component = next(value for value in bom["components"] if value["bom-ref"] == "http")
    component["purl"] = "pkg:npm/%40scope/demo-http@1.2.0"
    state = imported(journal, bom, context=qualified())
    derived = derive(journal, state)
    raw = report(derived)
    _, after, _, rows = execute(journal, data(state, derived, raw))
    assert not rows[0]["application_eligible"]
    raw["report"]["assessment"]["version_analysis"]["comparison_inputs"]["component_name"] = (
        "@scope/demo-http"
    )
    value = data(after, derived, raw).model_copy(update={"request_id": "qualified-package"})
    _, _, _, rows = execute(journal, value)
    assert sum(row["application_eligible"] for row in rows) == 1


def test_optional_native_guidance_is_preserved_without_becoming_source_verification(
    journal, inputs
):
    state, derived = inputs
    raw = report(derived)
    raw["job"]["request"]["user_guidance"] = "Review the exported API"
    raw["report"]["source_input"]["artifact_verified"] = True
    _, _, _, rows = execute(journal, data(state, derived, raw))
    assert rows[0]["application_eligible"]
    assert rows[0]["binary_binding_verified"] is False
    assert rows[0]["provider_authenticity"] == "caller_asserted_not_verified"
    assert journal.objects.read(rows[0]["report_sha256"]) == canonical(raw)
