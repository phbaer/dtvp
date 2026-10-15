"""Read-only DT source captures are frozen before journal baseline replacement."""

import copy
import json
from types import SimpleNamespace

import httpx
import pytest
import respx

from dtvp.knowledge.dependency_track import (
    DependencyTrackImportInput,
    collect_dependency_track,
    publish_dependency_track,
)
from dtvp.knowledge.journal import Conflict, Journal
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.storage import canonical, digest

EXTERNAL = "82cad190-a0f4-4e60-9c3d-76628440cd3b"
OTHER = "b4163a26-6841-48dc-8f21-75d99bdf6072"
BASE = "https://dt.example.invalid"


@pytest.fixture
def settings():
    return SimpleNamespace(dt_url=BASE, dt_api_key="read-only-key")


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def routes(bom, analysis=None, *, findings=None):
    raw_export = json.dumps(bom, ensure_ascii=False, indent=2).encode()
    export = respx.get(f"{BASE}/api/v1/bom/cyclonedx/project/{EXTERNAL}").mock(
        return_value=httpx.Response(200, content=raw_export)
    )
    finding = {
        "component": {
            "uuid": "dt-component",
            "bomRef": "http",
            "name": "demo-http",
            "version": "1.2.0",
            "purl": "pkg:npm/demo-http@1.2.0",
        },
        "vulnerability": {
            "uuid": "dt-vulnerability",
            "vulnId": "CVE-2099-20001",
            "source": "NVD",
            "description": "Imported advisory",
            "cvssV3Vector": bom["vulnerabilities"][0]["ratings"][0]["vector"],
            "cvssV3BaseScore": 9.8,
        },
        "analysis": {"analysisState": "NOT_AFFECTED", "analysisDetails": "Summary only"},
    }
    page = respx.get(f"{BASE}/api/v1/finding/project/{EXTERNAL}").mock(
        return_value=httpx.Response(200, json=findings if findings is not None else [finding])
    )
    full_analysis = (
        analysis
        if analysis is not None
        else {
            "analysis": {
                "analysisState": "NOT_AFFECTED",
                "analysisDetails": "Plain historical rationale",
                "isSuppressed": True,
            },
            "comments": [{"comment": "Legacy comment", "commenter": "claimed reviewer"}],
        }
    )
    detail = respx.get(f"{BASE}/api/v1/analysis").mock(
        return_value=httpx.Response(200, json=full_analysis)
    )
    return export, page, detail, raw_export


def args(**changes):
    return DependencyTrackImportInput(
        request_id="dt-build-1",
        expected=None,
        build_number=1,
        occurred_at="2026-10-15T06:00:00Z",
        **changes,
    )


def publish(journal, settings, capture, data=None, external=EXTERNAL):
    return publish_dependency_track(
        journal,
        settings=settings,
        external_project_id=external,
        capture=capture,
        project_id="product",
        version="7.1.1",
        actor_id="pipeline",
        data=data or args(),
    )


def persist(journal, artifacts):
    for sha, raw in artifacts.items():
        assert journal.objects.put(raw) == sha


@respx.mock
def test_exact_composition_and_full_legacy_evidence_are_retained_without_dt_writes(
    journal, settings, bom
):
    _, _, _, raw_export = routes(bom)
    capture, artifacts = collect_dependency_track(settings, EXTERNAL)
    assert capture["sbom"]["components"] == bom["components"]
    assert capture["sbom"]["dependencies"] == bom["dependencies"]
    assert capture["sbom"]["metadata"] == bom["metadata"]
    assert artifacts[digest(raw_export)] == raw_export
    assert (
        json.loads(raw_export)["vulnerabilities"] == bom["vulnerabilities"]
    )  # Original export is not overwritten.
    properties = {
        value["name"]: json.loads(value["value"])
        for value in capture["sbom"]["vulnerabilities"][0]["properties"]
        if value["name"] != "dtvp:dt-origin"
    }
    assert properties["dtvp:dt-source"]["component"]["uuid"] == "dt-component"
    assert properties["dtvp:dt-source"]["vulnerability"]["uuid"] == "dt-vulnerability"
    assert properties["dtvp:dt-analysis"]["comments"][0]["commenter"] == "claimed reviewer"
    assert all(call.request.method == "GET" for call in respx.calls)
    assert all(call.request.headers["X-Api-Key"] == "read-only-key" for call in respx.calls)
    assert "read-only-key" not in json.dumps(capture)
    persist(journal, artifacts)
    receipt = publish(journal, settings, capture)
    state = receipt[1].updates[0].target
    journal.verify_state(state)
    sections = load_sections(journal, state)
    provenance = sections["inventory"]["baseline"]["source_provenance"]
    assert provenance["external_project_id"] == EXTERNAL
    assert provenance["remote_snapshot_consistent"] is False
    assert set(artifacts) <= set(journal.state(state).artifacts)
    assert digest(canonical(capture)) in journal.state(state).artifacts
    assert provenance["capture_sha256"] == digest(canonical(capture))
    row = load_workspace(journal, state)["items"][0]
    assert row["coverage"]["status"] == "unassessed"
    assert row["published_score"] is None
    assert row["legacy_evidence"][0]["approved"] is False
    assert row["legacy_evidence"][0]["proposed_applicability"] == "not_affected"
    assert sections["assessments"] == sections["reviews"] == {}


@respx.mock
def test_frozen_capture_retry_never_refetches_or_changes_the_receipt(journal, settings, bom):
    routes(bom)
    capture, artifacts = collect_dependency_track(settings, EXTERNAL)
    persist(journal, artifacts)
    before_calls = len(respx.calls)
    first = publish(journal, settings, capture)
    assert publish(journal, settings, copy.deepcopy(capture)) == first
    assert len(respx.calls) == before_calls
    assert journal.head() == first[0]


@respx.mock
def test_fetch_failure_or_wrong_missing_analysis_body_cannot_replace_baseline(
    journal, settings, bom
):
    _, _, detail, _ = routes(bom)
    before = journal.head()
    detail.mock(return_value=httpx.Response(503, text="Unavailable"))
    with pytest.raises(httpx.HTTPStatusError):
        collect_dependency_track(settings, EXTERNAL)
    assert journal.head() == before
    detail.mock(return_value=httpx.Response(404, text="Unknown project"))
    with pytest.raises(httpx.HTTPStatusError):
        collect_dependency_track(settings, EXTERNAL)
    assert journal.head() == before


@respx.mock
def test_missing_analysis_exact_native_response_is_retained_as_unknown(journal, settings, bom):
    _, _, detail, _ = routes(bom)
    detail.mock(return_value=httpx.Response(404, text="No analysis exists."))
    capture, artifacts = collect_dependency_track(settings, EXTERNAL)
    assert b"No analysis exists." in artifacts.values()
    assert any(response["status"] == 404 for response in capture["source_provenance"]["responses"])
    persist(journal, artifacts)
    result = publish(journal, settings, capture)
    row = load_workspace(journal, result[1].updates[0].target)["items"][0]
    assert row["coverage"]["status"] == "unassessed"
    assert row["published_score"] is None


@pytest.mark.parametrize(
    "change", ["uuid", "endpoint", "capture", "missing_artifact", "provenance"]
)
@respx.mock
def test_frozen_source_integrity_and_current_server_binding_are_required(
    journal, settings, bom, change
):
    routes(bom)
    capture, artifacts = collect_dependency_track(settings, EXTERNAL)
    persist(journal, artifacts)
    external = EXTERNAL
    if change == "uuid":
        external = OTHER
    elif change == "endpoint":
        settings.dt_url = "https://another.invalid"
    elif change == "capture":
        capture["sbom"]["components"][0]["version"] = "wrong"
    elif change == "missing_artifact":
        journal.objects.path(capture["raw_artifact_shas"][0]).unlink()
    else:
        capture["source_provenance"]["remote_snapshot_consistent"] = True
    with pytest.raises(ValueError):
        publish(journal, settings, capture, external=external)
    assert journal.head() is None


@respx.mock
def test_explicit_source_key_prevents_authority_switch_and_old_build_replacement(
    journal, settings, bom
):
    routes(bom)
    capture, artifacts = collect_dependency_track(settings, EXTERNAL)
    persist(journal, artifacts)
    first = publish(journal, settings, capture)
    state = first[1].updates[0].target
    with pytest.raises(Conflict, match="newer"):
        publish(
            journal,
            settings,
            capture,
            args().model_copy(update={"request_id": "old-build", "expected": state}),
        )
    import_inventory(
        journal,
        project_id="product-other",
        version="7.1.1",
        actor_id="pipeline",
        request_id="file",
        expected=None,
        source="files",
        build_number=1,
        occurred_at="2026-10-15T06:00:00Z",
        sbom=bom,
    )
    existing = next(
        publication.updates[0].target
        for _, publication in reversed(list(journal.publications()))
        if publication.updates[0].ref.project_id == "product-other"
    )
    with pytest.raises(Conflict, match="authority"):
        publish_dependency_track(
            journal,
            settings=settings,
            external_project_id=EXTERNAL,
            capture=capture,
            project_id="product-other",
            version="7.1.1",
            actor_id="pipeline",
            data=args().model_copy(
                update={"expected": existing, "request_id": "switch", "build_number": 2}
            ),
        )


@pytest.mark.parametrize("kind", ["purl", "version", "duplicate"])
@respx.mock
def test_inconsistent_remote_finding_identity_or_pagination_is_rejected(settings, bom, kind):
    routes(bom)
    finding = {
        "component": {
            "uuid": "component-a",
            "bomRef": "http",
            "purl": "pkg:npm/demo-http@1.2.0",
            "version": "1.2.0",
        },
        "vulnerability": {"uuid": "advisory-a", "vulnId": "CVE-2099-20001"},
    }
    if kind == "purl":
        finding["component"]["purl"] = "pkg:npm/wrong@1.2.0"
    if kind == "version":
        finding["component"]["version"] = "9.9.9"
    values = [finding, copy.deepcopy(finding)] if kind == "duplicate" else [finding]
    respx.get(f"{BASE}/api/v1/finding/project/{EXTERNAL}").mock(
        return_value=httpx.Response(200, json=values)
    )
    with pytest.raises(ValueError, match="identity|repeated"):
        collect_dependency_track(settings, EXTERNAL)


def test_server_settings_and_bound_uuid_are_required_before_network(settings):
    for bad in ("not-a-uuid", "https://attacker.invalid/source"):
        with pytest.raises(ValueError, match="UUID"):
            collect_dependency_track(settings, bad)
    settings.dt_url = "https://user:secret@example.invalid"
    with pytest.raises(ValueError, match="configured"):
        collect_dependency_track(settings, EXTERNAL)


def test_importer_provenance_and_additional_artifacts_are_reachable_and_idempotent(journal, bom):
    sha = journal.objects.put(b"raw connector result")
    kwargs = dict(
        project_id="product",
        version="7.1.1",
        actor_id="pipeline",
        request_id="import",
        expected=None,
        source="connector",
        build_number=1,
        occurred_at="2026-10-15T06:00:00Z",
        sbom=bom,
        source_provenance={"remote_consistent": False},
        additional_artifacts=[sha],
    )
    first = import_inventory(journal, **kwargs)
    assert import_inventory(journal, **kwargs) == first
    state = first[1].updates[0].target
    assert sha in journal.state(state).artifacts
    assert (
        load_sections(journal, state)["inventory"]["baseline"]["source_provenance"]
        == kwargs["source_provenance"]
    )
    with pytest.raises(Conflict):
        import_inventory(journal, **{**kwargs, "source_provenance": {"changed": True}})


def test_missing_extra_artifact_fails_without_publication(journal, bom):
    with pytest.raises(ValueError, match="artifact unavailable"):
        import_inventory(
            journal,
            project_id="product",
            version="7.1.1",
            actor_id="pipeline",
            request_id="import",
            expected=None,
            source="connector",
            build_number=1,
            occurred_at="2026-10-15T06:00:00Z",
            sbom=bom,
            additional_artifacts=["f" * 64],
        )
    assert journal.head() is None


@pytest.mark.parametrize("qualitative_only", [False, True])
@respx.mock
def test_all_explicit_source_ratings_and_qualitative_severity_survive(
    journal, settings, bom, qualitative_only
):
    bom["vulnerabilities"] = copy.deepcopy(bom["vulnerabilities"])
    vector = bom["vulnerabilities"][0]["ratings"][0]["vector"]
    routes(bom)
    advisory = {"uuid": "advisory", "vulnId": "CVE-2099-20001", "severity": "HIGH"}
    if not qualitative_only:
        advisory.update(
            cvssV2Vector="AV:N/AC:L/Au:N/C:P/I:P/A:P",
            cvssV2BaseScore=7.5,
            cvssV3Vector=vector,
            cvssV3BaseScore=9.8,
        )
    finding = {"component": {"uuid": "component", "bomRef": "http"}, "vulnerability": advisory}
    respx.get(f"{BASE}/api/v1/finding/project/{EXTERNAL}").mock(
        return_value=httpx.Response(200, json=[finding])
    )
    if qualitative_only:
        bom["vulnerabilities"][0]["ratings"] = [{"severity": "high"}]
        respx.get(f"{BASE}/api/v1/bom/cyclonedx/project/{EXTERNAL}").mock(
            return_value=httpx.Response(200, json=bom)
        )
    capture, artifacts = collect_dependency_track(settings, EXTERNAL)
    ratings = capture["sbom"]["vulnerabilities"][0]["ratings"]
    assert all(rating["severity"] == "HIGH" for rating in ratings)
    assert len(ratings) == (1 if qualitative_only else 2)
    persist(journal, artifacts)
    receipt = publish(journal, settings, capture)
    row = load_workspace(journal, receipt[1].updates[0].target)["items"][0]
    assert row["source_severity"] == ("high" if qualitative_only else "critical")
    if qualitative_only:
        assert "score" not in ratings[0]


@respx.mock
def test_response_byte_limit_fails_before_any_publication(journal, settings, bom, monkeypatch):
    routes(bom)
    monkeypatch.setattr("dtvp.knowledge.dependency_track.MAX_RESPONSE_BYTES", 10)
    with pytest.raises(ValueError, match="byte limit"):
        collect_dependency_track(settings, EXTERNAL)
    assert journal.head() is None


@pytest.mark.parametrize("empty_findings", [False, True])
@respx.mock
def test_export_and_finding_api_claims_remain_distinct_in_workspace(
    journal, settings, bom, empty_findings
):
    export, page, _, _ = routes(bom)
    original = copy.deepcopy(bom)
    original["vulnerabilities"][0]["ratings"] = [{"score": 0, "severity": "none"}]
    original["vulnerabilities"][0]["properties"] = [
        {"name": "dtvp:dt-origin", "value": "finding-api"}
    ]
    export.mock(return_value=httpx.Response(200, json=original))
    if empty_findings:
        page.mock(return_value=httpx.Response(200, json=[]))
    capture, artifacts = collect_dependency_track(settings, EXTERNAL)
    persist(journal, artifacts)
    receipt = publish(journal, settings, capture)
    row = load_workspace(journal, receipt[1].updates[0].target)["items"][0]
    facts = row["sourcefacts"]
    assert len(facts) == (1 if empty_findings else 2)
    origins = {
        next(
            prop["value"]
            for prop in fact["advisory"]["properties"]
            if prop["name"] == "dtvp:dt-origin"
        )
        for fact in facts
    }
    assert origins == ({"sbom-export"} if empty_findings else {"sbom-export", "finding-api"})
    assert {rating.get("score") for rating in row["source_ratings"]} == (
        {0} if empty_findings else {0, 9.8}
    )
    assert row["coverage"]["status"] == "unassessed"
    assert row["published_score"] is None
