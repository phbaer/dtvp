"""Source-pinned external mocks exercise current sibling interfaces without services."""

import json
import os
from email import policy
from email.parser import BytesParser
from pathlib import Path

import httpx
import pytest
from jsonschema import Draft202012Validator

from dtvp.knowledge.agentyzer_results import (
    AgentyzerResultInput,
    import_agentyzer_result,
    list_agentyzer_results,
)
from dtvp.knowledge.issued_exports import issue_export
from dtvp.knowledge.journal import Ref, Update
from dtvp.knowledge.proposals import list_proposals
from dtvp.knowledge.vscorer import derive_context_inputs
from dtvp.knowledge.vscorer_minimal import VScorerMinimalProposalInput, import_minimal_proposal
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import digest
from tests.test_knowledge_agentyzer import VERSION, derive, imported, qualified
from tests.test_knowledge_agentyzer import journal as source_journal
from tests.test_knowledge_vscorer import prepare
from tests.test_knowledge_workspace import workspace as source_workspace
from tests.test_rescoring import BASE

workspace = source_workspace
journal = source_journal
ROOT = Path(__file__).parent / "fixtures/specialist_contracts"


def fixture(provider, model, suffix="schema"):
    return json.loads((ROOT / f"{provider}-{model}.{suffix}.json").read_bytes())


def validate(provider, model, value):
    Draft202012Validator(fixture(provider, model)).validate(value)


def multipart(request):
    message = BytesParser(policy=policy.default).parsebytes(
        (
            "Content-Type: " + request.headers["content-type"] + "\r\nMIME-Version: 1.0\r\n\r\n"
        ).encode()
        + request.content
    )
    return {
        part.get_param("name", header="content-disposition"): part.get_payload(decode=True)
        for part in message.iter_parts()
    }


@pytest.fixture
def issued(workspace):
    journal, state, context = prepare(workspace)
    journal.publish(
        request_id="mock-source",
        fingerprint=state,
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=None, target=state)],
    )
    payload = derive_context_inputs(
        journal, state, context["id"], "shared", {"CVE-2099-10001": BASE}
    )
    issued = issue_export(
        journal,
        project_id="product",
        actor_id="operator",
        state=state,
        kind="vscorer-input",
        payload=payload,
        selector={"context_id": context["id"]},
    )
    return journal, state, context, issued


def exchange(issued):
    journal, state, _, captured = issued
    finding = fixture("vscorer", "FindingResponse", "example")
    uploads = {}
    requests = []

    def server(request):
        requests.append(request.url.path)
        assert request.headers["idempotency-key"]
        assert request.headers["origin"] == "https://mock-vscorer.invalid"
        assert request.headers["x-csrf-token"] == "mock-session-csrf"
        assert "vscorer_session=mock-session" in request.headers["cookie"]
        if request.url.path == "/api/v1/artifacts":
            fields = multipart(request)
            kind = fields["kind"].decode()
            assert kind in {"sbom", "cves"}
            raw = fields["file"]
            assert raw == journal.objects.read(captured["files"][kind + ".json"]["sha256"])
            document = json.loads(raw)
            if kind == "cves":
                assert set(document) == {"cves"}
                assert set(document["cves"][0]) == {
                    "cve_id",
                    "component_refs",
                    "cvss_vector",
                    "base_score",
                    "description",
                    "cwe_ids",
                    "cpe",
                    "references",
                }
                assert document["cves"][0]["component_refs"] == ["shared"]
            else:
                assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6"
            response = {
                "id": kind + "-1",
                "kind": kind,
                "sha256": digest(raw),
                "original_filename": kind + ".json",
                "media_type": "application/json",
                "size_bytes": len(raw),
                "created_at": "2026-10-16T12:00:00Z",
                "_links": {"self": "/api/v1/artifacts/" + kind + "-1"},
            }
            validate("vscorer", "ArtifactResponse", response)
            uploads[kind] = response
            return httpx.Response(201, json=response)
        if request.url.path == "/api/v1/assessments":
            body = json.loads(request.content)
            validate("vscorer", "AssessmentCreateRequest", body)
            assert body["artifacts"]["sbom"] == uploads["sbom"]["id"]
            assert body["artifacts"]["cves"] == uploads["cves"]["id"]
            response = fixture("vscorer", "AssessmentResponse", "example")
            validate("vscorer", "AssessmentResponse", response)
            return httpx.Response(201, json=response)
        assert request.url.path == "/api/v1/assessments/assessment-1/findings/finding-1"
        validate("vscorer", "FindingResponse", finding)
        validate("vscorer", "PreviewResponse", finding["preview"])
        return httpx.Response(200, content=(json.dumps(finding, indent=2) + "\n").encode())

    with httpx.Client(
        base_url="https://mock-vscorer.invalid",
        transport=httpx.MockTransport(server),
        headers={
            "Idempotency-Key": "mock-request",
            "Origin": "https://mock-vscorer.invalid",
            "X-CSRF-Token": "mock-session-csrf",
            "Cookie": "vscorer_session=mock-session",
        },
    ) as client:
        for kind in ("sbom", "cves"):
            client.post(
                "/api/v1/artifacts",
                data={"kind": kind},
                files={
                    "file": (
                        kind + ".json",
                        journal.objects.read(captured["files"][kind + ".json"]["sha256"]),
                        "application/json",
                    )
                },
            ).raise_for_status()
        client.post(
            "/api/v1/assessments",
            json={
                "product_version_id": "version-1",
                "configuration_snapshot_id": "configuration-1",
                "artifacts": {
                    "threat_model": "tm7-operator-supplied",
                    "sbom": uploads["sbom"]["id"],
                    "cves": uploads["cves"]["id"],
                },
                "deployment_profile": {"mode": "none"},
            },
        ).raise_for_status()
        result = client.get("/api/v1/assessments/assessment-1/findings/finding-1")
    data = VScorerMinimalProposalInput(
        request_id="minimal-result",
        expected=state,
        issued_input_receipt_sha256=captured["receipt_sha256"],
        input_artifacts={
            kind: {"artifact_id": item["id"], "sha256": item["sha256"]}
            for kind, item in uploads.items()
        },
        assessment_id="assessment-1",
        mapping_mode="not_declared",
        finding_json=result.text,
        finding_sha256=digest(result.content),
        binding_reason="Operator captured these uploads and selected the matching assessment/finding; synthetic mocked exchange only.",
    )
    return data, finding, requests


def current_proposals(journal, state, context):
    return list_proposals(
        journal, load_sections(journal, state), "1", context["id"], "CVE-2099-10001"
    )


def test_current_vscorer_minimal_accepts_issued_inputs_without_fabricating_echoed_receipts(issued):
    journal, state, context, captured = issued
    data, finding, requests = exchange(issued)
    assert "dtvp_source" not in finding["source_facts"]
    before = load_sections(journal, state)
    result = import_minimal_proposal(
        journal, project_id="product", version="1", actor_id="operator", data=data
    )
    target = result[1].updates[0].target
    record = current_proposals(journal, target, context)[0]
    assert record["eligible"] and record["requires_coordinator_publication"]
    assert record["verification"] == "operator_bound_minimal_rest_exchange"
    assert record["binding_origin"] == "DTVP operator; not echoed by VScorer"
    assert record["provider_authenticity"] == "caller_asserted_not_verified"
    assert journal.objects.read(record["report_sha256"]) == data.finding_json.encode()
    assert json.loads(journal.objects.read(record["report_sha256"])) == finding
    assert load_sections(journal, target)["assessments"] == before["assessments"]
    assert requests == [
        "/api/v1/artifacts",
        "/api/v1/artifacts",
        "/api/v1/assessments",
        "/api/v1/assessments/assessment-1/findings/finding-1",
    ]
    assert captured["files"]["sbom.json"]["sha256"] == data.input_artifacts.sbom.sha256
    assert (
        import_minimal_proposal(
            journal, project_id="product", version="1", actor_id="operator", data=data
        )
        == result
    )


@pytest.mark.parametrize(
    "change",
    [
        "raw_hash",
        "input_hash",
        "assessment",
        "cve",
        "component",
        "version",
        "base",
        "invented_receipt",
        "preview_revision",
    ],
)
def test_minimal_exchange_rejects_inconsistent_operator_bindings_without_publication(
    issued, change
):
    journal, state, _, _ = issued
    data, finding, _ = exchange(issued)
    if change == "raw_hash":
        data.finding_sha256 = "0" * 64
    elif change == "input_hash":
        data.input_artifacts.sbom.sha256 = "0" * 64
    else:
        if change == "assessment":
            finding["assessment_id"] = "other"
        elif change == "cve":
            finding["cve_id"] = "CVE-2099-99999"
        elif change == "component":
            finding["source_facts"]["components"][0]["bom_ref"] = "other"
        elif change == "version":
            finding["source_facts"]["components"][0]["version"] = "2"
        elif change == "base":
            finding["source_facts"]["base_score"] = 0
        elif change == "invented_receipt":
            finding["source_facts"]["dtvp_source"] = {}
        else:
            finding["preview"]["finding_version"] = 99
        data.finding_json = json.dumps(finding)
        data.finding_sha256 = digest(data.finding_json.encode())
    references = journal.references()
    with pytest.raises(ValueError):
        import_minimal_proposal(
            journal, project_id="product", version="1", actor_id="operator", data=data
        )
    assert journal.references() == references
    assert journal.resolve(Ref(project_id="product", name="1")) == state


def test_incomplete_minimal_provider_scope_retains_a_blocked_proposal(issued):
    journal, _, context, _ = issued
    data, finding, _ = exchange(issued)
    finding["preview"]["scope_complete"] = False
    data.finding_json = json.dumps(finding)
    data.finding_sha256 = digest(data.finding_json.encode())
    result = import_minimal_proposal(
        journal, project_id="product", version="1", actor_id="operator", data=data
    )
    record = current_proposals(journal, result[1].updates[0].target, context)[0]
    assert (
        not record["eligible"]
        and "minimal_provider_scope_incomplete" in record["ineligibility_reasons"]
    )


def test_actual_agentyzer_contract_ignores_unknown_commit_and_retains_unqualified_result(
    journal, bom
):
    state = imported(journal, bom, context=qualified())
    derived = derive(journal, state)
    response = fixture("agentyzer", "AssessResponse", "example")
    validate("agentyzer", "AssessResponse", response)
    allowed = fixture("agentyzer", "AssessRequest")["properties"]
    assert "source_commit" not in allowed
    calls = []
    echoed = {}

    def server(request):
        calls.append((request.method, request.url.path))
        if request.url.path == "/assess":
            submitted = json.loads(request.content)
            validate("agentyzer", "AssessRequest", submitted)
            echoed.update({key: value for key, value in submitted.items() if key in allowed})
            submitted = fixture("agentyzer", "JobSubmittedResponse", "example")
            validate("agentyzer", "JobSubmittedResponse", submitted)
            return httpx.Response(200, json=submitted)
        if request.url.path == "/jobs/job-1":
            status = fixture("agentyzer", "JobStatusResponse", "example")
            status["request"] = dict(echoed)
            validate("agentyzer", "JobStatusResponse", status)
            return httpx.Response(200, json=status)
        assert request.url.path == "/jobs/job-1/result"
        return httpx.Response(200, json=response)

    with httpx.Client(
        base_url="https://mock-agentyzer.invalid", transport=httpx.MockTransport(server)
    ) as client:
        client.post("/assess", json=derived["request"]).raise_for_status()
        job = client.get("/jobs/job-1").json()
        report = client.get("/jobs/job-1/result").json()
    assert "source_commit" not in job["request"] and "source_input" not in report
    envelope = {"format": "dtvp.agentyzer-result-envelope/1", "job": job, "report": report}
    result = import_agentyzer_result(
        journal,
        project_id="product",
        version=VERSION,
        actor_id="operator",
        data=AgentyzerResultInput(
            request_id="current-default",
            expected=state,
            input_receipt=derived["receipt"],
            raw_report=envelope,
        ),
    )
    target = result[1].updates[0].target
    records = list_agentyzer_results(
        journal,
        load_sections(journal, target),
        VERSION,
        derived["receipt"]["context_id"],
        derived["receipt"]["vulnerability_id"],
    )
    assert len(records) == 1
    record = records[0]
    assert not record["application_eligible"] and not record["rescoring_eligible"]
    assert "provider_source_commit_binding_unavailable" in record["source_blockers"]
    assert json.loads(journal.objects.read(record["report_sha256"])) == envelope
    assert (
        load_sections(journal, target)["assessments"]
        == load_sections(journal, state)["assessments"]
    )
    assert calls == [("POST", "/assess"), ("GET", "/jobs/job-1"), ("GET", "/jobs/job-1/result")]


def test_frozen_specialist_schemas_have_recorded_source_and_exact_hashes():
    manifest = json.loads((ROOT / "sources.json").read_bytes())
    assert manifest["format"] == "dtvp.specialist-mock-contracts/1"
    for provider in manifest["providers"].values():
        assert len(provider["commit"]) == 40
        for item in provider["schemas"]:
            assert digest((ROOT / item["file"]).read_bytes()) == item["sha256"]
        assert provider["source_files"]


def test_optional_current_sibling_contract_drift_check():
    root = os.getenv("DTVP_SPECIALIST_SOURCE_ROOT")
    if not root:
        pytest.skip("Set DTVP_SPECIALIST_SOURCE_ROOT to explicitly check sibling source drift")
    manifest = json.loads((ROOT / "sources.json").read_bytes())
    for provider, description in manifest["providers"].items():
        for item in description["source_files"]:
            assert digest((Path(root) / provider / item["path"]).read_bytes()) == item["sha256"], (
                f"{provider}/{item['path']} changed; review and refresh contract snapshots explicitly"
            )


def test_minimal_proposal_http_route_uses_native_authorization_and_explicit_publication(
    issued, analyst, app
):
    from sqlalchemy import select

    from dtvp.models import Project, Workspace

    journal, _, context, _ = issued
    data, _, _ = exchange(issued)
    with app.state.sessions.begin() as db:
        workspace = db.scalar(select(Workspace).where(Workspace.name == "Platform"))
        db.add(Project(id="product", workspace_id=workspace.id, name="Mocked specialist contract"))
    app.state.knowledge = journal
    response = analyst.post(
        "/api/v3/projects/product/versions/1/proposals/vscorer-minimal",
        json=data.model_dump(mode="json"),
    )
    assert response.status_code == 201, response.text
    state = response.json()["updates"][0]["target"]
    assert (
        current_proposals(journal, state, context)[0]["verification"]
        == "operator_bound_minimal_rest_exchange"
    )
    assert (
        analyst.post(
            "/api/v3/projects/absent/versions/1/proposals/vscorer-minimal",
            json=data.model_dump(mode="json"),
        ).status_code
        == 404
    )


@pytest.fixture
def mapped_issued(workspace):
    from tests.test_pipeline_consumer_metadata import setup

    journal, state, context, _, _ = setup(workspace)
    payload = derive_context_inputs(
        journal, state, context["id"], "shared", {"CVE-2099-10001": BASE}
    )
    captured = issue_export(
        journal,
        project_id="product",
        actor_id="operator",
        state=state,
        kind="vscorer-input",
        payload=payload,
        selector={"context_id": context["id"]},
    )
    return journal, state, context, captured


def mapping_selection(captured):
    from dtvp.knowledge.vscorer_minimal import MinimalMappingSelection

    return MinimalMappingSelection(
        issued_input_receipt_sha256=captured["receipt_sha256"],
        model_id="model",
        model_revision="revision-one",
        model_sha256="a" * 64,
    )


def test_explicit_minimal_items_csv_uses_issued_context_without_changing_old_serialized_inputs(
    mapped_issued,
):
    from dtvp.knowledge.vscorer_minimal import derive_minimal_mapping

    journal, _, context, captured = mapped_issued
    before = journal.references()
    files = {name: journal.objects.read(meta["sha256"]) for name, meta in captured["files"].items()}
    report = derive_minimal_mapping(journal, project_id="product", data=mapping_selection(captured))
    assert report["items_csv"] == "component_ref;threat_model_element_id\nshared;explicit-id\n"
    assert report["items_csv_sha256"] == digest(report["items_csv"].encode())
    assert report["context_id"] == context["id"] and report["committed"] is False
    assert "not_authenticated" in report["assurance"]
    assert journal.references() == before
    assert files == {
        name: journal.objects.read(meta["sha256"]) for name, meta in captured["files"].items()
    }
    data, _, _ = exchange(mapped_issued)
    data.mapping_mode = "issued_items_csv"
    data.mapping_selection = mapping_selection(captured)
    from dtvp.knowledge.vscorer_minimal import UploadedInput

    data.input_artifacts.items_csv = UploadedInput(
        artifact_id="items-1", sha256=report["items_csv_sha256"]
    )
    data.input_artifacts.threat_model = UploadedInput(artifact_id="tm7-1", sha256="a" * 64)
    result = import_minimal_proposal(
        journal, project_id="product", version="1", actor_id="operator", data=data
    )
    record = current_proposals(journal, result[1].updates[0].target, context)[0]
    assert record["mapping_mode"] == "issued_items_csv"
    assert record["mapping_report_digest"] == report["report_digest"]
    assert json.loads(journal.objects.read(record["mapping_report_sha256"])) == report
    assert journal.objects.read(record["mapping_csv_sha256"]) == report["items_csv"].encode()
    assert {record["mapping_report_sha256"], record["mapping_csv_sha256"]} <= set(
        journal.state(result[1].updates[0].target).artifacts
    )
    assert record["input_declarations"]["threat_model"]["sha256"] == "a" * 64


@pytest.mark.parametrize("change", ["model", "revision", "digest"])
def test_minimal_mapping_requires_exact_explicit_model_selection(mapped_issued, change):
    from dtvp.knowledge.vscorer_minimal import derive_minimal_mapping

    journal, _, _, captured = mapped_issued
    selection = mapping_selection(captured)
    if change == "model":
        selection.model_id = "other"
    elif change == "revision":
        selection.model_revision = "different"
    else:
        selection.model_sha256 = "b" * 64
    with pytest.raises(ValueError, match="revision/digest"):
        derive_minimal_mapping(journal, project_id="product", data=selection)


@pytest.fixture
def actual_job_env(tmp_path, bom):
    from tests.test_knowledge_analysis_jobs import env

    yield from env.__wrapped__(tmp_path, bom)


def test_native_worker_observes_current_agentyzer_contract_and_retains_missing_commit_proof(
    actual_job_env, monkeypatch
):
    import dtvp.knowledge.analysis_jobs as module
    from tests.test_knowledge_analysis_jobs import enqueue, job, run

    env = actual_job_env
    allowed = fixture("agentyzer", "AssessRequest")["properties"]
    echoed = {}
    calls = []

    def server(request):
        calls.append(request.url.path)
        if request.url.path == "/assess":
            submitted = json.loads(request.content)
            validate("agentyzer", "AssessRequest", submitted)
            echoed.update({key: value for key, value in submitted.items() if key in allowed})
            response = fixture("agentyzer", "JobSubmittedResponse", "example")
            validate("agentyzer", "JobSubmittedResponse", response)
        elif request.url.path == "/jobs/job-1":
            response = fixture("agentyzer", "JobStatusResponse", "example")
            response["request"] = dict(echoed)
            validate("agentyzer", "JobStatusResponse", response)
        else:
            assert request.url.path == "/jobs/job-1/result"
            response = fixture("agentyzer", "AssessResponse", "example")
            validate("agentyzer", "AssessResponse", response)
        return httpx.Response(200, json=response)

    monkeypatch.setattr(
        module, "client", lambda: httpx.Client(transport=httpx.MockTransport(server))
    )
    identity = enqueue(env)
    run(env, identity)
    stored = job(env, identity)
    assert stored.status == "succeeded"
    sections = load_sections(env.journal, stored.result["state"])
    records = list_agentyzer_results(
        env.journal,
        sections,
        VERSION,
        env.derived["receipt"]["context_id"],
        env.derived["receipt"]["vulnerability_id"],
    )
    assert (
        len(records) == 1
        and not records[0]["application_eligible"]
        and not records[0]["rescoring_eligible"]
    )
    assert "provider_source_commit_binding_unavailable" in records[0]["source_blockers"]
    assert calls == ["/assess", "/jobs/job-1", "/jobs/job-1/result"]
    assert sections["assessments"] == load_sections(env.journal, env.state)["assessments"]


@pytest.mark.parametrize("kind", ["duplicate_member", "nonfinite", "deep"])
def test_minimal_raw_result_rejects_ambiguous_or_unbounded_json_before_publication(issued, kind):
    journal, _, _, _ = issued
    data, _, _ = exchange(issued)
    if kind == "duplicate_member":
        raw = '{"assessment_id":"assessment-1","assessment_id":"other"}'
    elif kind == "nonfinite":
        raw = '{"unsupported":NaN}'
    else:
        raw = '{"nested":' + "[" * 1500 + "null" + "]" * 1500 + "}"
    data.finding_json = raw
    data.finding_sha256 = digest(raw.encode())
    before = journal.references()
    with pytest.raises(ValueError):
        import_minimal_proposal(
            journal, project_id="product", version="1", actor_id="operator", data=data
        )
    assert journal.references() == before


@pytest.mark.parametrize("change", ["csv", "tm7", "undeclared"])
def test_minimal_mapping_binding_rejects_changed_files_or_implicit_mapping_claims(
    mapped_issued, change
):
    from dtvp.knowledge.vscorer_minimal import UploadedInput, derive_minimal_mapping

    journal, _, _, captured = mapped_issued
    data, _, _ = exchange(mapped_issued)
    selection = mapping_selection(captured)
    report = derive_minimal_mapping(journal, project_id="product", data=selection)
    data.mapping_mode = "issued_items_csv"
    data.mapping_selection = selection
    data.input_artifacts.items_csv = UploadedInput(
        artifact_id="items-1", sha256=report["items_csv_sha256"]
    )
    data.input_artifacts.threat_model = UploadedInput(
        artifact_id="tm7-1", sha256=selection.model_sha256
    )
    if change == "csv":
        data.input_artifacts.items_csv.sha256 = "0" * 64
    elif change == "tm7":
        data.input_artifacts.threat_model.sha256 = "0" * 64
    else:
        data.mapping_mode = "not_declared"
    before = journal.references()
    with pytest.raises(ValueError):
        import_minimal_proposal(
            journal, project_id="product", version="1", actor_id="operator", data=data
        )
    assert journal.references() == before


def test_minimal_mapping_rejects_multiple_context_rows_even_when_ids_repeat(
    mapped_issued, monkeypatch
):
    import copy

    import dtvp.knowledge.vscorer_minimal as module

    journal, _, _, captured = mapped_issued
    changed = copy.deepcopy(captured)
    rows = changed["payload"]["pipeline_context"]["rows"]
    rows.append(copy.deepcopy(rows[0]))
    monkeypatch.setattr(module, "resolve_issued_export", lambda *args, **kwargs: changed)
    with pytest.raises(ValueError, match="ambiguous"):
        module.derive_minimal_mapping(
            journal, project_id="product", data=mapping_selection(captured)
        )
