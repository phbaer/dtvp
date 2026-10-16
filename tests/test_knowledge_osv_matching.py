"""External OSV claims remain scoped, frozen and distinct from human applicability."""

import copy
from types import SimpleNamespace

import httpx
import pytest

from dtvp.knowledge import osv_matching as module
from dtvp.knowledge.advisory_sources import baseline_identifiers
from dtvp.knowledge.evidence import current_evidence
from dtvp.knowledge.journal import Conflict
from dtvp.storage import canonical, digest
from tests.test_knowledge_advisory_documents import add, facts, feed, heads, inventory
from tests.test_knowledge_advisory_documents import journal as source_journal

journal = source_journal
PURL = "pkg:npm/demo-http@1.2.0"
NOVEL = "CVE-2099-30001"


def upstream(identifier=NOVEL):
    return {
        "id": identifier,
        "details": "Provider match, not human applicability.",
        "modified": "2026-10-16T00:00:00Z",
        "aliases": ["GHSA-not-merged"],
        "affected": [
            {
                "package": {"purl": "pkg:npm/demo-http"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            }
        ],
    }


def data(journal, purls=None, **changes):
    return module.MatchingInput(
        **(
            {
                "request_id": "matching",
                "expected_versions": heads(journal),
                "expected_evidence": current_evidence(journal, "product")[0],
                "purls": purls or [PURL],
                "revision": 0,
            }
            | changes
        )
    )


def collected(journal, response=None, *, purl=PURL):
    response = {"vulns": [upstream()]} if response is None else response
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))
    ) as client:
        query, artifacts = module.read_query(client, purl)
    for sha, raw in artifacts.items():
        assert journal.objects.put(raw) == sha
    return {
        "format": module.CAPTURE_FORMAT,
        "purls": [purl],
        "queries": [query],
        "started_at": "2026-10-16T00:00:00Z",
        "completed_at": "2026-10-16T00:01:00Z",
    }


def publish(journal, capture, selected=None):
    return module.publish_matches(
        journal,
        settings=SimpleNamespace(providers_enabled=["osv"]),
        project_id="product",
        actor_id="analyst",
        data=selected or data(journal),
        capture=capture,
    )


def test_novel_external_matching_enriches_exact_id_without_alias_identity_or_approval(journal, bom):
    inventory(journal, bom)
    capture = collected(journal)
    receipt = publish(journal, capture)
    claims = [row for row in facts(journal) if row["identifier"] == NOVEL]
    assert len(claims) == 1 and claims[0]["kind"] == "external-match"
    assert claims[0]["advisory"]["normalized_status"] is None
    assert claims[0]["advisory"]["aliases"] == [{"id": "GHSA-not-merged", "source": "OSV"}]
    assert NOVEL in baseline_identifiers(journal, "product", heads(journal))
    add(journal, feed(NOVEL), request_id="enrichment")
    assert {row["kind"] for row in facts(journal) if row["identifier"] == NOVEL} == {
        "external-match",
        "external-advisory",
    }
    state = heads(journal)["1"]
    assert all(
        not journal.records(state, section) for section in ("assessments", "reviews", "scoring")
    )
    assert digest(canonical(capture)) in journal.state(receipt[1].updates[0].target).artifacts


def test_empty_query_retires_only_its_own_source_and_advisory_cannot_amplify_stale_matches(
    journal, bom
):
    inventory(journal, bom)
    publish(journal, collected(journal))
    add(journal, feed(NOVEL), request_id="enrichment")
    other_purl = "pkg:pypi/demo-parser@2.0.0"
    publish(
        journal,
        collected(journal, {"vulns": [upstream("CVE-2099-30002")]}, purl=other_purl),
        data(journal, [other_purl], request_id="other-query"),
    )
    publish(journal, collected(journal, {}), data(journal, request_id="empty-refresh", revision=1))
    assert NOVEL not in baseline_identifiers(journal, "product", heads(journal))
    assert not [row for row in facts(journal) if row["identifier"] == NOVEL]
    assert [row for row in facts(journal) if row["identifier"] == "CVE-2099-30002"]
    _, documents = current_evidence(journal, "product")
    checked = [
        record
        for record in documents.values()
        if record.get("active", True)
        and record["document"].get("matching_coverage", {}).get("purl") == PURL
    ]
    assert (
        len(checked) == 1
        and checked[0]["document"]["matching_coverage"]["status"] == "no_matches_reported"
    )


@pytest.mark.parametrize("change", ["purl", "contradictory_version", "qualified"])
def test_changed_package_purl_never_reuses_old_matches_or_grows_known_id_set(journal, bom, change):
    inventory(journal, bom)
    publish(journal, collected(journal))
    changed = copy.deepcopy(bom)
    if change == "purl":
        changed["components"][0].update(version="1.3.0", purl="pkg:npm/demo-http@1.3.0")
    elif change == "contradictory_version":
        changed["components"][0]["version"] = "1.3.0"
    else:
        changed["components"][0]["purl"] = PURL + "?arch=x86"
    inventory(journal, changed, build=2)
    assert NOVEL not in baseline_identifiers(journal, "product", heads(journal))
    assert not [row for row in facts(journal) if row["identifier"] == NOVEL]


def test_empty_page_with_token_is_followed_and_requests_bind_version_only_in_purl():
    requests = []

    def transport(request):
        body = __import__("json").loads(request.content)
        requests.append(body)
        return httpx.Response(
            200, json={"next_page_token": "next"} if len(requests) == 1 else {"vulns": [upstream()]}
        )

    with httpx.Client(transport=httpx.MockTransport(transport)) as client:
        result, artifacts = module.read_query(client, PURL)
    assert requests == [
        {"package": {"purl": PURL}},
        {"package": {"purl": PURL}, "page_token": "next"},
    ]
    assert (
        result["coverage"] == "matches_reported"
        and len(result["pages"]) == 2
        and len(artifacts) == 2
    )


@pytest.mark.parametrize(
    "response", [{"vulns": "bad"}, {"vulns": [upstream(), upstream()]}, {"next_page_token": []}]
)
def test_bad_provider_results_fail_closed(response):
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))
    ) as client:
        with pytest.raises(ValueError):
            module.read_query(client, PURL)


def test_repeating_token_and_page_byte_budget_stop_before_unbounded_collection(monkeypatch):
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"next_page_token": "same"})
        )
    ) as client:
        with pytest.raises(ValueError, match="repeated"):
            module.read_query(client, PURL)
    monkeypatch.setattr(module, "MAX_PAGE", 1)
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={}))
    ) as client:
        with pytest.raises(ValueError, match="byte budget"):
            module.read_query(client, PURL)


def test_frozen_raw_binding_tamper_and_branch_cas_fail_without_publication(journal, bom):
    inventory(journal, bom)
    selected = data(journal)
    capture = collected(journal)
    tampered = copy.deepcopy(capture)
    tampered["queries"][0]["matches"][0]["advisory"]["description"] = "Altered"
    with pytest.raises(ValueError, match="normalization"):
        publish(journal, tampered, selected)
    changed = copy.deepcopy(bom)
    inventory(journal, changed, version="2")
    with pytest.raises(Conflict):
        publish(journal, capture, selected)


def test_exact_receipt_precedes_changed_heads_and_changed_capture_conflicts(
    journal, bom, monkeypatch
):
    inventory(journal, bom)
    selected, capture = data(journal), collected(journal)
    first = publish(journal, capture, selected)
    monkeypatch.setattr(
        module, "validate_inputs", lambda *_: pytest.fail("Exact receipt must precede head checks")
    )
    assert publish(journal, capture, selected) == first
    changed = copy.deepcopy(capture)
    changed["completed_at"] = "2026-10-17T00:00:00Z"
    with pytest.raises(Conflict):
        publish(journal, changed, selected)


def test_same_package_used_twice_keeps_distinct_occurrences(journal, bom):
    value = copy.deepcopy(bom)
    value["components"].append({**value["components"][0], "bom-ref": "second-http"})
    inventory(journal, value)
    publish(journal, collected(journal))
    assert {row["ref"] for row in facts(journal) if row["identifier"] == NOVEL} == {
        "http",
        "second-http",
    }


def test_selection_unknowns_are_explicit_and_qualified_unversioned_inputs_rejected(journal, bom):
    value = copy.deepcopy(bom)
    value["components"][0]["purl"] = "pkg:npm/demo-http@1.2.0?arch=x86"
    value["components"][1]["purl"] = "pkg:pypi/demo-parser"
    inventory(journal, value)
    coverage = module.selection(journal, "product", heads(journal))
    assert coverage["unsupported_occurrences"]["qualified_or_subpath_purl"] == 1
    assert coverage["unsupported_occurrences"]["unversioned_purl"] == 1
    assert coverage["unqueried_coverage"] == "unknown"
    for purl in ("pkg:npm/library", "pkg:npm/library@1?arch=x86"):
        with pytest.raises(ValueError):
            data(journal, [purl])


def test_provider_withdrawal_retires_only_this_source_claim_without_proving_remediation(
    journal, bom
):
    inventory(journal, bom)
    publish(journal, collected(journal))
    withdrawn = upstream() | {"withdrawn": "2026-10-16T01:00:00Z"}
    publish(
        journal,
        collected(journal, {"vulns": [withdrawn]}),
        data(journal, request_id="withdrawn-refresh", revision=1),
    )
    assert NOVEL not in baseline_identifiers(journal, "product", heads(journal))
    assert not [row for row in facts(journal) if row["identifier"] == NOVEL]
    _, documents = current_evidence(journal, "product")
    current = [record for record in documents.values() if record.get("active", True)]
    assert current[0]["document"]["statements"][0]["unresolved_reasons"] == [
        "provider_record_withdrawn"
    ]
    assert current[0]["document"]["raw"]["matches"][0]["raw"]["withdrawn"] == withdrawn["withdrawn"]


@pytest.mark.parametrize("budget", ["source", "context"])
def test_fanout_preflight_rejects_before_any_new_snapshot(journal, bom, monkeypatch, budget):
    from dtvp.knowledge.journal import Ref, Update
    from dtvp.knowledge.workspace import load_sections

    original = inventory(journal, bom)
    sections = load_sections(journal, original)
    sections["ownership"]["context:capacity-one"] = {"component_ref": "http"}
    sections["ownership"]["context:capacity-two"] = {"component_ref": "http"}
    state = journal.snapshot(
        project_id="product",
        version="1",
        actor_id="owner",
        reason="Context capacity fixture",
        sections=sections,
        parents=[original],
    )
    journal.publish(
        request_id="contexts",
        fingerprint=digest(b"contexts"),
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=original, target=state)],
    )
    selected = data(journal)
    capture = collected(journal)
    monkeypatch.setattr(
        module,
        "MAX_SOURCE_OBSERVATIONS" if budget == "source" else "MAX_CONTEXT_FINDINGS",
        0 if budget == "source" else 1,
    )
    before = journal.head(), journal.references()
    monkeypatch.setattr(
        journal, "snapshot", lambda **_: pytest.fail("Fanout must be admitted before snapshots")
    )
    with pytest.raises(ValueError, match="fanout"):
        publish(journal, capture, selected)
    assert before == (journal.head(), journal.references())


def test_frozen_replay_validator_rejects_repeated_provider_page_tokens(journal, bom):
    inventory(journal, bom)
    pages, matches = [], []
    token = None
    for index, next_token in enumerate(("loop", "loop", None)):
        item = upstream(f"CVE-2099-5000{index}")
        raw = canonical(
            {"vulns": [item], **({"next_page_token": next_token} if next_token else {})}
        )
        sha = journal.objects.put(raw)
        pages.append(
            {
                "method": "POST",
                "url": module.ENDPOINT,
                "status": 200,
                "request": {"package": {"purl": PURL}, **({"page_token": token} if token else {})},
                "sha256": sha,
                "bytes": len(raw),
            }
        )
        matches.append(module.normalize_match(item))
        token = next_token
    capture = {
        "format": module.CAPTURE_FORMAT,
        "purls": [PURL],
        "queries": [
            {
                "purl": PURL,
                "pages": pages,
                "matches": matches,
                "coverage": "matches_reported",
                "observed_at": "2026-10-16T00:00:00Z",
            }
        ],
        "completed_at": "2026-10-16T00:01:00Z",
    }
    with pytest.raises(ValueError, match="token.*repeated"):
        publish(journal, capture)


def test_assembled_part_roots_match_as_distinct_current_occurrences(journal):
    from dtvp.knowledge.journal import SECTIONS
    from dtvp.knowledge.vex import matching_source_refs, parse_evidence, reconcile_evidence

    sections = {name: {} for name in SECTIONS}
    sections["inventory"] = {
        "part-root:first": {"bom-ref": "first-root", "purl": PURL, "version": "1.2.0"},
        "part-root:second": {"bom-ref": "second-root", "purl": PURL, "version": "1.2.0"},
    }
    document = {
        "format": module.FORMAT,
        "id": "osv-purl:" + digest(canonical(PURL)),
        "publisher": "OSV",
        "purl": PURL,
        "observed_at": "2026-10-16T00:00:00Z",
        "coverage": "matches_reported",
        "matches": [module.normalize_match(upstream())],
    }
    raw = canonical(document)
    sections["vulnerabilities"]["evidence-document:" + digest(raw)] = {
        "document": parse_evidence(raw),
        "artifact_sha": digest(raw),
        "source": "connector:osv-matching",
        "active": True,
    }
    reconcile_evidence(sections)
    claims = [
        value
        for key, value in sections["vulnerabilities"].items()
        if key.startswith("external-evidence:")
    ]
    assert {value["ref"] for value in claims} == {"first-root", "second-root"}
    assert matching_source_refs(sections)[NOVEL] == {"first-root", "second-root"}
