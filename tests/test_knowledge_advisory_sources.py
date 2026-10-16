"""Exact-ID provider capture/catalog behavior without live external requests."""

import copy
from types import SimpleNamespace

import httpx
import pytest
import respx

from dtvp.knowledge.advisory_sources import (
    ENDPOINTS,
    AdvisoryRefreshInput,
    collect_advisories,
    publish_advisories,
)
from dtvp.knowledge.evidence import current_evidence
from dtvp.knowledge.journal import Conflict
from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.storage import canonical, digest
from tests.test_knowledge_advisory_documents import facts, heads, inventory
from tests.test_knowledge_advisory_documents import journal as source_journal

journal = source_journal

FIRST = "CVE-2099-20001"
SECOND = "CVE-2099-20002"
BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.fixture
def settings():
    return SimpleNamespace(providers_enabled=["nvd", "circl"])


def upstream(identifier, provider="nvd", *, found=True):
    if not found:
        return {"vulnerabilities": []} if provider == "nvd" else {}
    if provider == "nvd":
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": identifier,
                        "descriptions": [{"lang": "en", "value": "Provider description"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "claimed-publisher",
                                    "cvssData": {"vectorString": BASE_VECTOR, "baseScore": 0},
                                }
                            ]
                        },
                        "references": [{"url": "https://source.invalid/advisory"}],
                    }
                }
            ]
        }
    return {
        "cveMetadata": {"cveId": identifier},
        "containers": {
            "cna": {
                "providerMetadata": {"shortName": "Claimed CNA"},
                "descriptions": [{"lang": "en", "value": "CNA description"}],
                "references": [{"url": "https://source.invalid/cna"}],
                "metrics": [{"cvssV3_1": {"vectorString": BASE_VECTOR, "baseScore": 0}}],
            }
        },
    }


def route(identifier, provider="nvd", body=None):
    url = ENDPOINTS[provider] + (identifier if provider == "circl" else "")
    return respx.get(url, params={"cveId": identifier} if provider == "nvd" else None).mock(
        return_value=httpx.Response(
            200, json=upstream(identifier, provider) if body is None else body
        )
    )


def data(journal, identifiers=None, **changes):
    return AdvisoryRefreshInput(
        **(
            {
                "request_id": "refresh-1",
                "provider": "nvd",
                "identifiers": identifiers or [FIRST],
                "expected_evidence": current_evidence(journal, "product")[0],
                "expected_versions": heads(journal),
                "revision": 1,
            }
            | changes
        )
    )


def captured(settings, journal, identifiers=None, provider="nvd"):
    capture, artifacts = collect_advisories(settings, provider, identifiers or [FIRST])
    for sha, raw in artifacts.items():
        assert journal.objects.put(raw) == sha
    return capture


def publish(journal, settings, value, capture):
    return publish_advisories(
        journal,
        settings=settings,
        project_id="product",
        actor_id="pipeline",
        data=value,
        capture=capture,
    )


@pytest.mark.parametrize("provider", ["nvd", "circl"])
@respx.mock
def test_provider_capture_preserves_claims_raw_bodies_and_pinned_source_base(
    journal, settings, bom, provider
):  # noqa: F811
    original = inventory(journal, bom)
    before = load_sections(journal, original)
    route(FIRST, provider)
    value = data(journal, provider=provider)
    capture = captured(settings, journal, provider=provider)
    receipt = publish(journal, settings, value, capture)
    assert publish(journal, settings, value, copy.deepcopy(capture)) == receipt
    claim = facts(journal)[0]
    assert claim["source"] == "connector:" + provider
    assert claim["advisory"]["ratings"][0]["score"] == 0
    assert claim["statement"]["raw"]["provider_entry"]["raw"]["provider_result"][
        "upstream"
    ] == upstream(FIRST, provider)
    state = heads(journal)["1"]
    for sha in [digest(canonical(capture)), *capture["raw_artifact_shas"]]:
        assert sha in journal.verify_state(state).artifacts
    after = load_sections(journal, state)
    for section in ("inventory", "assessments", "reviews", "scoring"):
        assert after[section] == before[section]
    row = next(
        row for row in load_workspace(journal, state)["items"] if row["vulnerability_id"] == FIRST
    )
    assert {rating["score"] for rating in row["source_ratings"]} == {0, 9.8}
    assert row["published_score"] is None
    assert all(call.request.method == "GET" for call in respx.calls)
    assert len(respx.calls) == 1


@respx.mock
def test_partial_catalog_refresh_retains_untouched_ids_and_all_missing_yields_empty_catalog(
    journal, settings, bom
):  # noqa: F811
    inventory(journal, bom)
    route(FIRST)
    route(SECOND)
    publish(
        journal,
        settings,
        data(journal, [FIRST, SECOND]),
        captured(settings, journal, [FIRST, SECOND]),
    )
    assert {claim["identifier"] for claim in facts(journal)} == {FIRST, SECOND}
    route(FIRST, body=upstream(FIRST, found=False))
    publish(
        journal,
        settings,
        data(journal, request_id="partial", revision=2),
        captured(settings, journal),
    )
    assert [claim["identifier"] for claim in facts(journal)] == [SECOND]
    route(SECOND, body=upstream(SECOND, found=False))
    publish(
        journal,
        settings,
        data(journal, [SECOND], request_id="empty", revision=3),
        captured(settings, journal, [SECOND]),
    )
    assert facts(journal) == []
    rows = load_workspace(journal, heads(journal)["1"])["items"]
    assert {row["vulnerability_id"] for row in rows} == {FIRST, SECOND}
    _, records = current_evidence(journal, "product")
    active = next(record for record in records.values() if record["active"])
    assert active["document"]["raw"]["advisories"] == []
    assert active["document"]["raw"]["refresh"]["lookups"][0]["status"] == "not_found"


@pytest.mark.parametrize("provider", ["nvd", "circl"])
@respx.mock
def test_mismatched_upstream_identifier_or_malformed_shape_never_publishes(
    journal, settings, bom, provider
):  # noqa: F811
    inventory(journal, bom)
    route(FIRST, provider, upstream(SECOND, provider))
    before = journal.head()
    with pytest.raises(ValueError, match="identifier"):
        captured(settings, journal, provider=provider)
    assert journal.head() == before
    route(FIRST, provider, [])
    with pytest.raises(ValueError):
        captured(settings, journal, provider=provider)
    assert journal.head() == before


@respx.mock
def test_capture_cas_conflict_and_uncertain_replay_never_refetch_or_repin(journal, settings, bom):  # noqa: F811
    inventory(journal, bom)
    route(FIRST)
    value = data(journal)
    capture = captured(settings, journal)
    publish(journal, settings, value, capture)
    before, calls = journal.head(), len(respx.calls)
    assert publish(journal, settings, value, capture)
    assert journal.head() == before and len(respx.calls) == calls
    with pytest.raises(Conflict):
        publish(journal, settings, value.model_copy(update={"request_id": "new-request"}), capture)
    assert journal.head() == before


def test_disabled_invalid_ids_and_quota_fail_before_network(settings):
    settings.providers_enabled = []
    with pytest.raises(ValueError, match="disabled"):
        collect_advisories(settings, "nvd", [FIRST])
    settings.providers_enabled = ["nvd"]
    for identifiers in ([FIRST] * 21, [FIRST, FIRST], ["https://attacker.invalid"], []):
        with pytest.raises(ValueError):
            collect_advisories(settings, "nvd", identifiers)


@respx.mock
def test_response_budget_and_missing_artifacts_fail_without_publication(
    journal, settings, bom, monkeypatch
):  # noqa: F811
    inventory(journal, bom)
    route(FIRST)
    capture = captured(settings, journal)
    before = journal.head()
    journal.objects.path(capture["raw_artifact_shas"][0]).unlink()
    with pytest.raises((ValueError, OSError)):
        publish(journal, settings, data(journal), capture)
    assert journal.head() == before
    monkeypatch.setattr("dtvp.knowledge.advisory_sources.MAX_RESPONSE_BYTES", 10)
    with pytest.raises(ValueError, match="budget"):
        captured(settings, journal)
    assert journal.head() == before


@respx.mock
def test_unknown_ids_cannot_enter_native_refresh_even_when_provider_has_result(
    journal, settings, bom
):  # noqa: F811
    inventory(journal, bom)
    route("CVE-2099-99999")
    capture = captured(settings, journal, ["CVE-2099-99999"])
    before = journal.head()
    with pytest.raises(ValueError, match="baseline"):
        publish(journal, settings, data(journal, ["CVE-2099-99999"]), capture)
    assert journal.head() == before


def test_additional_evidence_artifacts_fail_closed_and_are_receipt_bound(journal, monkeypatch):  # noqa: F811
    from dtvp.knowledge.evidence import EvidenceInput, import_evidence
    from tests.test_knowledge_advisory_documents import feed

    value = EvidenceInput(
        request_id="artifacts",
        expected_evidence=None,
        expected_versions={},
        source="provider",
        revision=1,
        document=feed(),
    )
    with pytest.raises(ValueError, match="artifact unavailable"):
        import_evidence(
            journal,
            project_id="product",
            actor_id="pipeline",
            data=value,
            additional_artifacts=["f" * 64],
        )
    sha = journal.objects.put(b"source evidence")
    monkeypatch.setattr("dtvp.knowledge.evidence.MAX_ADDITIONAL_ARTIFACT_BYTES", 2)
    with pytest.raises(ValueError, match="budget"):
        import_evidence(
            journal,
            project_id="product",
            actor_id="pipeline",
            data=value,
            additional_artifacts=[sha],
        )
    assert journal.head() is None
    monkeypatch.setattr("dtvp.knowledge.evidence.MAX_ADDITIONAL_ARTIFACT_BYTES", 1024)
    receipt = import_evidence(
        journal, project_id="product", actor_id="pipeline", data=value, additional_artifacts=[sha]
    )
    assert sha in journal.verify_state(receipt[1].updates[0].target).artifacts
    with pytest.raises(Conflict):
        import_evidence(journal, project_id="product", actor_id="pipeline", data=value)


@respx.mock
def test_ambiguous_json_and_inconsistent_nvd_count_are_rejected(settings):
    bad = canonical(upstream(FIRST)).replace(
        b'"id":"' + FIRST.encode() + b'"',
        b'"id":"' + FIRST.encode() + b'","id":"' + FIRST.encode() + b'"',
    )
    handler = route(FIRST)
    handler.mock(return_value=httpx.Response(200, content=bad))
    with pytest.raises(ValueError, match="Duplicate"):
        collect_advisories(settings, "nvd", [FIRST])
    handler.mock(return_value=httpx.Response(200, json={"vulnerabilities": [], "totalResults": 1}))
    with pytest.raises(ValueError, match="count"):
        collect_advisories(settings, "nvd", [FIRST])


@respx.mock
def test_provider_redirect_cannot_contact_another_endpoint(settings):
    route(FIRST).mock(
        return_value=httpx.Response(302, headers={"location": "https://attacker.invalid/data"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        collect_advisories(settings, "nvd", [FIRST])
    assert len(respx.calls) == 1


@respx.mock
def test_new_branch_recovers_untouched_catalog_entry_from_pinned_evidence_ancestry(
    journal, settings, bom
):  # noqa: F811
    inventory(journal, bom)
    route(FIRST)
    route(SECOND)
    original_raw = canonical(upstream(SECOND))
    route(SECOND).mock(return_value=httpx.Response(200, content=original_raw))
    initial_capture = captured(settings, journal, [FIRST, SECOND])
    publish(journal, settings, data(journal, [FIRST, SECOND]), initial_capture)
    original_capture_sha = digest(canonical(initial_capture))
    original_raw_sha = next(
        item["response_sha256"]
        for item in initial_capture["results"]
        if item["identifier"] == SECOND
    )
    route(FIRST, body=upstream(FIRST, found=False))
    publish(
        journal,
        settings,
        data(journal, request_id="partial-for-future-branch", revision=2),
        captured(settings, journal),
    )
    selected_evidence = current_evidence(journal, "product")[0]
    state = inventory(journal, bom, version="future")
    revision = journal.verify_state(state)
    assert selected_evidence in revision.parents
    # Product artifacts are not an unbounded copy of historical response bodies;
    # the exact selected evidence parent retains the immutable capture closure.
    evidence_revision = journal.verify_state(selected_evidence)
    assert {original_capture_sha, original_raw_sha} <= set(evidence_revision.artifacts)
    claim = facts(journal, "future")[0]
    source = claim["statement"]["raw"]["provider_entry"]["raw"]
    assert source["capture_sha256"] == original_capture_sha
    assert source["response_sha256"] == original_raw_sha
    assert journal.load(original_capture_sha) == initial_capture
    assert journal.objects.read(original_raw_sha) == original_raw
    from dtvp.knowledge.evidence import resolve_evidence_artifact

    assert (
        resolve_evidence_artifact(journal, "product", selected_evidence, original_raw_sha)
        == selected_evidence
    )
    assert resolve_evidence_artifact(journal, "product", state, original_raw_sha) is None


@respx.mock
def test_evidence_artifact_resolver_rejects_unpublished_foreign_and_unrelated_roots(
    journal, settings, bom
):  # noqa: F811
    from dtvp.knowledge.evidence import resolve_evidence_artifact
    from dtvp.knowledge.journal import CorruptJournal

    inventory(journal, bom)
    route(FIRST)
    capture = captured(settings, journal)
    publish(journal, settings, data(journal), capture)
    selected = current_evidence(journal, "product")[0]
    sha = capture["raw_artifact_shas"][0]
    unrelated = journal.objects.put(b"unrelated raw data")
    assert resolve_evidence_artifact(journal, "product", selected, unrelated) is None
    assert resolve_evidence_artifact(journal, "other", selected, sha) is None
    unpublished = journal.snapshot(
        project_id="product",
        version="@evidence",
        actor_id="test",
        reason="Unpublished evidence",
        sections=load_sections(journal, selected),
        artifacts=[sha],
    )
    assert resolve_evidence_artifact(journal, "product", unpublished, sha) is None
    journal.objects.path(sha).unlink()
    with pytest.raises(CorruptJournal):
        resolve_evidence_artifact(journal, "product", selected, sha)
