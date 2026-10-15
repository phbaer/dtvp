"""Issued files survive code changes; native receipts remain exact and immutable."""

import copy
from uuid import uuid4

import pytest

from dtvp.knowledge.issued_exports import (
    find_issued_export,
    index_ref,
    issue_export,
    material_fingerprint,
    receipt_ref,
    resolve_issued_export,
    selector_ref,
)
from dtvp.knowledge.journal import Conflict, CorruptJournal, Journal, Ref, Update
from dtvp.knowledge.vscorer import derive_context_inputs
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest
from tests.test_knowledge_agentyzer import VERSION, derive, imported, qualified
from tests.test_rescoring import BASE


@pytest.fixture
def inputs(tmp_path, bom):
    journal = Journal(tmp_path / "journal")
    state = imported(journal, bom, context=qualified())
    return journal, state, derive(journal, state)


def issue(inputs, *, kind="knowledge-bundle", payload=None, selector=None, actor="issuer"):
    journal, state, _ = inputs
    return issue_export(
        journal,
        project_id="product",
        actor_id=actor,
        state=state,
        kind=kind,
        payload=payload,
        selector=selector,
    )


def publish(journal, parent, sections, *, version=VERSION):
    state = journal.snapshot(
        project_id="product",
        version=version,
        actor_id="fixture",
        reason="Fixture update",
        sections=sections,
        parents=[parent],
        artifacts=journal.state(parent).artifacts,
    )
    ref = Ref(project_id="product", name=version)
    journal.publish(
        request_id=str(uuid4()),
        fingerprint=digest(state.encode()),
        updates=[Update(ref=ref, expected=journal.resolve(ref), target=state)],
    )
    return state


def test_issue_pins_exact_files_and_source_parent_without_changing_product_heads(inputs):
    journal, state, _ = inputs
    old = journal.references()
    before = material_fingerprint(journal, state)
    result = issue(inputs)
    assert result["source_receipt"]["format"] == "dtvp.knowledge-bundle-source/1"
    assert result["source_receipt"]["bundle_sha256"] == result["files"]["bundle.json"]["sha256"]
    assert result["material_fingerprint"] == before
    assert result["material_fingerprint_id"] == "dtvp.material-fingerprint/1"
    assert result["serializer_id"] == "dtvp.knowledge-bundle-serializer/1"
    for ref, value in old.items():
        assert journal.references()[ref] == value
    assert len(journal.references()) == len(old) + 1
    node = journal.verify_state(result["issuance_state"])
    assert node.parents == [state] and node.version == "@export/" + result["receipt_sha256"]
    assert journal.records(result["issuance_state"], "inventory") == {}
    for file in result["files"].values():
        assert file["sha256"] in node.artifacts
        assert len(journal.objects.read(file["sha256"])) == file["bytes"]
    head = journal.head()
    assert issue(inputs, actor="second-authorized-reader") == result
    assert journal.head() == head


@pytest.mark.parametrize("kind", ["vscorer-input", "agentyzer-input"])
def test_native_issued_payloads_and_receipts_are_unchanged(inputs, kind):
    journal, state, analysis = inputs
    if kind == "vscorer-input":
        payload = derive_context_inputs(
            journal, state, analysis["receipt"]["context_id"], "http", {"CVE-2099-20001": BASE}
        )
        receipt = payload["dtvp_source"]
    else:
        payload, receipt = analysis, analysis["receipt"]
    selector = {"context_id": receipt["context_id"], "explicit": kind}
    result = issue(inputs, kind=kind, payload=payload, selector=selector)
    assert result["payload"] == payload and result["source_receipt"] == receipt
    assert result["receipt_sha256"] == digest(canonical(receipt))
    assert (
        resolve_issued_export(journal, "product", digest(canonical(receipt)), kind=kind) == result
    )
    assert (
        find_issued_export(journal, "product", state=state, kind=kind, selector=selector) == result
    )
    if kind == "vscorer-input":
        for key in ("sbom", "cves"):
            assert journal.objects.read(result["files"][key + ".json"]["sha256"]) == canonical(
                payload[key]
            )
    else:
        assert journal.objects.read(result["files"]["request.json"]["sha256"]) == canonical(
            payload["request"]
        )


def test_resolve_and_cached_issue_do_not_reserialize_or_rederive_after_upgrade(inputs, monkeypatch):
    journal, state, _ = inputs
    expected = issue(inputs)

    def unavailable(*args, **kwargs):
        raise AssertionError("A historical issuance must not call today's serializer")

    monkeypatch.setattr("dtvp.knowledge.issued_exports.export_bytes", unavailable)
    monkeypatch.setattr("dtvp.knowledge.issued_exports.material_fingerprint", unavailable)
    assert resolve_issued_export(journal, "product", expected["receipt_sha256"]) == expected
    assert (
        find_issued_export(journal, "product", state=state, kind="knowledge-bundle", selector={})
        == expected
    )
    assert issue(inputs) == expected


def test_different_payload_or_selector_never_overwrites_existing_receipt(inputs):
    journal, _, analysis = inputs
    expected = issue(
        inputs, kind="agentyzer-input", payload=analysis, selector={"scope": "original"}
    )
    head = journal.head()
    altered = copy.deepcopy(analysis)
    altered["coverage"]["reasons"].append("Different serializer output")
    with pytest.raises(Conflict, match="different serialized"):
        issue(inputs, kind="agentyzer-input", payload=altered, selector={"scope": "original"})
    with pytest.raises(Conflict, match="different issued selector"):
        issue(inputs, kind="agentyzer-input", payload=analysis, selector={"scope": "different"})
    assert journal.head() == head
    assert resolve_issued_export(journal, "product", expected["receipt_sha256"]) == expected


@pytest.mark.parametrize("index", [False, True])
def test_reserved_issuance_and_selector_refs_cannot_be_overwritten(inputs, index):
    journal, state, _ = inputs
    issued = issue(inputs)
    old = issued["issuance_state"]
    ref = (
        selector_ref("product", state, "knowledge-bundle", {})[0]
        if index
        else receipt_ref("product", issued["receipt_sha256"])
    )
    journal.publish(
        request_id="legacy-ref-" + str(index),
        fingerprint=digest(ref.key.encode()),
        updates=[Update(ref=ref, expected=None, target=old)],
    )
    replacement = journal.snapshot(
        project_id="product",
        version=journal.state(old).version,
        actor_id="test",
        reason="Attempt rewrite",
        sections=load_sections(journal, old),
        parents=[old],
        artifacts=journal.state(old).artifacts,
    )
    head = journal.head()
    with pytest.raises(Conflict, match="immutable"):
        journal.publish(
            request_id="overwrite",
            fingerprint=digest(b"overwrite"),
            updates=[Update(ref=ref, expected=old, target=replacement)],
        )
    assert journal.head() == head and journal.resolve(ref) == old


def test_missing_artifact_is_corruption_and_never_an_unissued_fallback(inputs):
    journal, state, _ = inputs
    issued = issue(inputs)
    journal.objects.path(issued["files"]["payload.json"]["sha256"]).unlink()
    with pytest.raises(CorruptJournal):
        resolve_issued_export(journal, "product", issued["receipt_sha256"])
    with pytest.raises(CorruptJournal):
        find_issued_export(journal, "product", state=state, kind="knowledge-bundle", selector={})
    assert resolve_issued_export(journal, "product", "f" * 64) is None


def test_inconsistent_selector_reference_fails_closed(inputs):
    journal, state, _ = inputs
    issued = issue(inputs)
    from dtvp.knowledge.issued_exports import BUCKET_FORMAT, INDEX_FORMAT

    old = journal.resolve(index_ref("product"))
    _, selector = selector_ref("product", state, "knowledge-bundle", {"different": True})
    sections = load_sections(journal, old)
    buckets = sections["history"]["issued-export-index"]["buckets"]
    bucket = journal.store(
        {"format": BUCKET_FORMAT, "entries": {"selector:" + selector: issued["issuance_state"]}}
    )
    buckets[selector[:2]] = bucket
    sections["history"]["issued-export-index"]["format"] = INDEX_FORMAT
    new = journal.snapshot(
        project_id="product",
        version="@export-index",
        actor_id="test",
        reason="Corrupt index fixture",
        sections=sections,
        parents=[old],
        artifacts=list(buckets.values()),
    )
    journal.publish(
        request_id="invalid-selector",
        fingerprint=digest(b"invalid"),
        updates=[Update(ref=index_ref("product"), expected=old, target=new)],
    )
    with pytest.raises(CorruptJournal):
        find_issued_export(
            journal, "product", state=state, kind="knowledge-bundle", selector={"different": True}
        )


def test_cross_project_or_changed_native_file_hash_is_rejected_without_publication(inputs):
    journal, state, analysis = inputs
    before = journal.head()
    with pytest.raises(ValueError, match="one product|product"):
        issue_export(
            journal, project_id="other", actor_id="issuer", state=state, kind="knowledge-bundle"
        )
    wrong = copy.deepcopy(analysis)
    wrong["receipt"]["state"] = "f" * 64
    with pytest.raises(ValueError, match="scope"):
        issue(inputs, kind="agentyzer-input", payload=wrong)
    wrong = copy.deepcopy(analysis)
    wrong["request"]["vuln_id"] = "CVE-OTHER"
    with pytest.raises(ValueError, match="request differs"):
        issue(inputs, kind="agentyzer-input", payload=wrong)
    assert journal.head() == before


def test_material_digest_excludes_only_document_bookkeeping_not_license_or_metadata(inputs):
    journal, state, _ = inputs
    original = material_fingerprint(journal, state)
    sections = load_sections(journal, state)
    sections["history"]["document:report"] = {"revision": "draft"}
    sections["history"]["document-review:report"] = {"action": "approve"}
    bookkeeping = publish(journal, state, sections)
    assert material_fingerprint(journal, bookkeeping) == original
    sections["history"]["license-disposition:component"] = {"disposition": "restricted"}
    license_state = publish(journal, bookkeeping, sections)
    assert material_fingerprint(journal, license_state) != original
    sections["history"]["metadata:component"] = {"usage": "different deployment"}
    metadata_state = publish(journal, license_state, sections)
    assert material_fingerprint(journal, metadata_state) != material_fingerprint(
        journal, license_state
    )
    another_version = publish(journal, metadata_state, sections, version="7.1.2")
    assert material_fingerprint(journal, another_version) != material_fingerprint(
        journal, metadata_state
    )


def test_concurrent_identical_issuance_reuses_atomic_published_capture(inputs, monkeypatch):
    journal, state, _ = inputs
    native = Journal.publish
    raced = []

    def publish_race(self, **kwargs):
        if not raced and kwargs["updates"][0].ref.name == "consumer-export-index":
            raced.append(True)
            issue_export(
                journal,
                project_id="product",
                actor_id="another-issuer",
                state=state,
                kind="knowledge-bundle",
            )
        return native(self, **kwargs)

    monkeypatch.setattr(Journal, "publish", publish_race)
    issued = issue(inputs)
    assert issued["issued_by"] == "another-issuer"
    assert resolve_issued_export(journal, "product", issued["receipt_sha256"]) == issued
    assert len([key for key in journal.references() if "consumer-export" in key]) == 1


def test_unpublished_product_candidate_cannot_issue_or_advance_journal_head(inputs):
    journal, state, _ = inputs
    sections = load_sections(journal, state)
    sections["inventory"]["root"]["version"] = "unpublished-candidate"
    candidate = journal.snapshot(
        project_id="product",
        version=VERSION,
        actor_id="candidate",
        reason="Unpublished candidate",
        sections=sections,
        parents=[state],
        artifacts=journal.state(state).artifacts,
    )
    before = journal.head()
    with pytest.raises(ValueError, match="committed product history"):
        issue_export(
            journal,
            project_id="product",
            actor_id="issuer",
            state=candidate,
            kind="knowledge-bundle",
        )
    assert journal.head() == before
    assert len(journal.references()) == 1


def test_many_exports_have_one_project_ref_and_preserve_old_bucket_objects(inputs):
    journal, state, _ = inputs
    original_count = len(journal.references())
    captures = []
    first_buckets = None
    for number in range(12):
        if number:
            sections = load_sections(journal, state)
            sections["history"]["fixture"] = {"number": number}
            state = publish(journal, state, sections)
        captures.append(
            issue_export(
                journal,
                project_id="product",
                actor_id="issuer",
                state=state,
                kind="knowledge-bundle",
            )
        )
        root = journal.resolve(index_ref("product"))
        buckets = journal.load(journal.records(root, "history")["issued-export-index"])["buckets"]
        first_buckets = first_buckets or dict(buckets)
        assert len(journal.references()) == original_count + 1
        assert len(buckets) <= 256
    for sha in first_buckets.values():
        assert journal.load(sha)["entries"]
    for capture in captures:
        assert resolve_issued_export(journal, "product", capture["receipt_sha256"]) == capture


def test_concurrent_different_exports_merge_index_without_losing_receipts(inputs, monkeypatch):
    journal, state, analysis = inputs
    native = Journal.publish
    concurrent = []

    def race(self, **kwargs):
        if not concurrent and kwargs["updates"][0].ref == index_ref("product"):
            concurrent.append(None)
            concurrent[0] = issue_export(
                journal,
                project_id="product",
                actor_id="other",
                state=state,
                kind="agentyzer-input",
                payload=analysis,
            )
        return native(self, **kwargs)

    monkeypatch.setattr(Journal, "publish", race)
    issued = issue(inputs)
    assert resolve_issued_export(journal, "product", issued["receipt_sha256"]) == issued
    assert (
        resolve_issued_export(journal, "product", concurrent[0]["receipt_sha256"]) == concurrent[0]
    )
    assert len(journal.references()) == 2


def test_missing_index_bucket_fails_closed_even_for_unknown_receipt(inputs):
    journal, _, _ = inputs
    issue(inputs)
    root = journal.resolve(index_ref("product"))
    buckets = journal.load(journal.records(root, "history")["issued-export-index"])["buckets"]
    journal.objects.path(next(iter(buckets.values()))).unlink()
    with pytest.raises(CorruptJournal):
        resolve_issued_export(journal, "product", "f" * 64)
