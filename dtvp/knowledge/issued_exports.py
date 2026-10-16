"""Immutable emitted consumer inputs, independent of mutable serializer implementations."""

import json
from datetime import UTC, datetime
from typing import Literal

from dtvp.knowledge.comparison import product_state, reachable_states
from dtvp.knowledge.exports import export_bytes
from dtvp.knowledge.journal import SECTIONS, Conflict, CorruptJournal, Ref, Update
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

Kind = Literal["knowledge-bundle", "vscorer-input", "agentyzer-input"]
PREFIX = "consumer-export/"
FORMAT = "dtvp.issued-export/1"
MATERIAL_FORMAT = "dtvp.material-fingerprint/1"
SERIALIZERS = {kind: "dtvp." + kind + "-serializer/1" for kind in Kind.__args__}
DOCUMENT_PREFIXES = ("document:", "document-review:", "issued-export:")
MAX_BYTES = 256 * 1024 * 1024


def material_fingerprint(journal, state):
    """Conservative model facts; registry bookkeeping never makes a report stale.

    Source/import changes conservatively count even when a later reviewer might
    establish equivalent meaning. This digest is not approval or output validation.
    """
    revision = product_state(journal, state, journal.state(state).project_id)
    sections = load_sections(journal, state)
    sections["history"] = {
        key: value
        for key, value in sections["history"].items()
        if not key.startswith(DOCUMENT_PREFIXES)
    }
    return digest(canonical([MATERIAL_FORMAT, revision.version, sections]))


def receipt_ref(project_id, receipt_sha):
    return Ref(kind="evidence", project_id=project_id, name=PREFIX + receipt_sha)


def selector_ref(project_id, state, kind, selector):
    sha = digest(canonical([project_id, state, kind, selector]))
    return Ref(kind="evidence", project_id=project_id, name=PREFIX + "selector/" + sha), sha


INDEX_FORMAT = "dtvp.issued-export-index/1"
BUCKET_FORMAT = "dtvp.issued-export-bucket/1"


def index_ref(project_id):
    return Ref(kind="evidence", project_id=project_id, name="consumer-export-index")


def _index(journal, project_id):
    state = journal.resolve(index_ref(project_id))
    if state is None:
        return None, {}
    try:
        revision = journal.verify_state(state)
        record = journal.load(journal.records(state, "history")["issued-export-index"])
        buckets = record["buckets"]
        if (
            revision.project_id != project_id
            or revision.version != "@export-index"
            or record["format"] != INDEX_FORMAT
            or not isinstance(buckets, dict)
            or any(
                len(key) != 2 or any(c not in "0123456789abcdef" for c in key) for key in buckets
            )
            or not set(buckets.values()).issubset(revision.artifacts)
        ):
            raise ValueError("Invalid issued export index")
        return state, buckets
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        raise CorruptJournal("Issued export index is corrupt") from error


def _lookup(journal, buckets, key):
    prefix = key.split(":", 1)[1][:2]
    sha = buckets.get(prefix)
    if sha is None:
        return None
    try:
        bucket = journal.load(sha)
        if bucket["format"] != BUCKET_FORMAT or not isinstance(bucket["entries"], dict):
            raise ValueError("Invalid issued export bucket")
        return bucket["entries"].get(key)
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        raise CorruptJournal("Issued export bucket is corrupt") from error


def _scope(receipt, project_id, version, state):
    if not isinstance(receipt, dict) or any(
        receipt.get(key) != value
        for key, value in {"project_id": project_id, "version": version, "state": state}.items()
    ):
        raise ValueError("Native consumer receipt differs from the issued source scope")


def _inputs(kind, payload, bundle, manifest, project_id, version, state):
    files = {"bundle.json": bundle, "manifest.json": canonical(manifest)}
    if kind == "knowledge-bundle":
        native = json.loads(bundle)
        if payload is not None and payload != native:
            raise ValueError("Knowledge export payload must equal the exact native bundle")
        payload = native
        receipt = {
            "format": "dtvp.knowledge-bundle-source/1",
            "project_id": project_id,
            "version": version,
            "state": state,
            "bundle_sha256": digest(bundle),
        }
    elif kind == "vscorer-input":
        receipt = payload.get("dtvp_source") if isinstance(payload, dict) else None
        _scope(receipt, project_id, version, state)
        if receipt.get("format") != "dtvp.vscorer-source/1" or receipt.get(
            "bundle_sha256"
        ) != digest(bundle):
            raise ValueError("VScorer source receipt differs from its native bundle")
        artifacts = receipt.get("artifacts", {})
        for key in ("sbom", "cves"):
            raw = canonical(payload[key])
            if artifacts.get(key + "_sha256") != digest(raw):
                raise ValueError("VScorer input file differs from its source receipt")
            files[key + ".json"] = raw
        if "pipeline_context" in payload:
            from dtvp.knowledge.exports import contextual_pipeline_metadata

            expected_context = contextual_pipeline_metadata(
                json.loads(bundle), receipt["context_id"]
            )
            raw = canonical(payload["pipeline_context"])
            if payload["pipeline_context"] != expected_context or artifacts.get(
                "pipeline_context_sha256"
            ) != digest(raw):
                raise ValueError(
                    "VScorer pipeline metadata differs from its pinned bundle or receipt"
                )
            files["pipeline-context.json"] = raw
        elif "pipeline_context_sha256" in artifacts or "pipeline_context" in json.loads(bundle):
            raise ValueError("VScorer pipeline metadata is missing from its declared source")
    elif kind == "agentyzer-input":
        receipt = payload.get("receipt") if isinstance(payload, dict) else None
        _scope(receipt, project_id, version, state)
        if receipt.get("format") != "dtvp.agentyzer-source/1":
            raise ValueError("Unsupported Agentyzer source receipt")
        request = payload.get("request")
        if (digest(canonical(request)) if request is not None else None) != receipt.get(
            "request_sha256"
        ):
            raise ValueError("Agentyzer request differs from its source receipt")
        files["request.json"] = canonical(request)
    else:
        raise ValueError("Unsupported issued consumer export kind")
    _scope(receipt, project_id, version, state)
    files["payload.json"], files["receipt.json"] = canonical(payload), canonical(receipt)
    if sum(len(raw) for raw in {digest(raw): raw for raw in files.values()}.values()) > MAX_BYTES:
        raise ValueError("Issued consumer export exceeds its 256 MiB artifact budget")
    return payload, receipt, files


def _verify_capture(journal, record, payload, receipt):
    files = record["files"]

    def read(name):
        return json.loads(journal.objects.read(files[name]["sha256"]))

    bundle, manifest = read("bundle.json"), read("manifest.json")
    for value in (bundle, manifest):
        _scope(value, record["project_id"], record["version"], record["source_state"])
    if (
        bundle.get("format") != "dtvp.knowledge-bundle/1"
        or manifest.get("format") != "dtvp.knowledge-export/1"
        or manifest.get("bundle_format") != bundle["format"]
        or manifest.get("bundle_sha256") != files["bundle.json"]["sha256"]
        or manifest.get("bundle_bytes") != files["bundle.json"]["bytes"]
        or files["receipt.json"]["sha256"] != record["receipt_sha256"]
    ):
        raise ValueError("Issued bundle/manifest content binding differs")
    if record["kind"] == "knowledge-bundle":
        if payload != bundle or receipt.get("bundle_sha256") != manifest["bundle_sha256"]:
            raise ValueError("Issued knowledge payload differs")
    elif record["kind"] == "vscorer-input":
        if (
            payload.get("dtvp_source") != receipt
            or receipt.get("bundle_sha256") != manifest["bundle_sha256"]
        ):
            raise ValueError("Issued VScorer receipt differs")
        for key in ("sbom", "cves"):
            if receipt["artifacts"][key + "_sha256"] != files[key + ".json"]["sha256"] or payload[
                key
            ] != read(key + ".json"):
                raise ValueError("Issued VScorer file differs")
        if "pipeline_context" in payload:
            from dtvp.knowledge.exports import contextual_pipeline_metadata

            expected_context = contextual_pipeline_metadata(bundle, receipt["context_id"])
            if (
                payload["pipeline_context"] != expected_context
                or payload["pipeline_context"] != read("pipeline-context.json")
                or receipt["artifacts"].get("pipeline_context_sha256")
                != files["pipeline-context.json"]["sha256"]
            ):
                raise ValueError("Issued VScorer pipeline metadata differs")
        elif (
            "pipeline_context_sha256" in receipt.get("artifacts", {})
            or "pipeline-context.json" in files
            or "pipeline_context" in bundle
        ):
            raise ValueError("Issued VScorer pipeline metadata binding is missing")
    elif record["kind"] == "agentyzer-input":
        if payload.get("receipt") != receipt or payload.get("request") != read("request.json"):
            raise ValueError("Issued Agentyzer payload differs")
        if (
            payload.get("request") is not None
            and receipt.get("request_sha256") != files["request.json"]["sha256"]
        ):
            raise ValueError("Issued Agentyzer request differs")
    else:
        raise ValueError("Unsupported issued consumer kind")


def _read(
    journal,
    project_id,
    issuance_state,
    *,
    receipt_sha=None,
    selector_sha=None,
    kind=None,
    buckets=None,
):
    """An existing reference is authoritative; corruption is never a missing receipt."""
    try:
        revision = journal.verify_state(issuance_state)
        record_sha = journal.records(issuance_state, "history").get("issued-export")
        if not record_sha:
            raise ValueError("Issuance record missing")
        record = journal.load(record_sha)
        expected_receipt = record["receipt_sha256"]
        if (
            record.get("format") != FORMAT
            or record.get("project_id") != project_id
            or revision.project_id != project_id
            or revision.version != "@export/" + expected_receipt
            or (receipt_sha is not None and receipt_sha != expected_receipt)
            or (selector_sha is not None and selector_sha != record["selector_sha256"])
            or (kind is not None and record["kind"] != kind)
        ):
            raise ValueError("Issuance identity mismatch")
        if buckets is None:
            _, buckets = _index(journal, project_id)
        if _lookup(journal, buckets, "receipt:" + expected_receipt) != issuance_state:
            raise ValueError("Issuance receipt index mismatch")
        _, computed_selector = selector_ref(
            project_id, record["source_state"], record["kind"], record["selector"]
        )
        if (
            computed_selector != record["selector_sha256"]
            or _lookup(journal, buckets, "selector:" + computed_selector) != issuance_state
        ):
            raise ValueError("Issuance selector reference mismatch")
        source = product_state(journal, record["source_state"], project_id)
        if source.version != record["version"] or record["source_state"] not in revision.parents:
            raise ValueError("Issuance source parent mismatch")
        shas = {file["sha256"] for file in record["files"].values()}
        if not shas.issubset(revision.artifacts):
            raise ValueError("Issuance artifacts are not pinned")
        for file in record["files"].values():
            if len(journal.objects.read(file["sha256"])) != file["bytes"]:
                raise ValueError("Issuance artifact length mismatch")
        payload = json.loads(journal.objects.read(record["files"]["payload.json"]["sha256"]))
        receipt = json.loads(journal.objects.read(record["files"]["receipt.json"]["sha256"]))
        if digest(canonical(receipt)) != expected_receipt:
            raise ValueError("Issuance source receipt digest mismatch")
        _scope(receipt, project_id, source.version, record["source_state"])
        _verify_capture(journal, record, payload, receipt)
        # Do not call export_bytes, derive functions or material_fingerprint here.
        # The captured bytes, scope and immutable roots survive serializer upgrades.
        return {
            **record,
            "issuance_state": issuance_state,
            "source_receipt": receipt,
            "payload": payload,
        }
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        raise CorruptJournal("Issued consumer export is corrupt or incompatible") from error


def resolve_issued_export(journal, project_id, receipt_sha, *, kind=None):
    _, buckets = _index(journal, project_id)
    state = _lookup(journal, buckets, "receipt:" + receipt_sha)
    return (
        _read(journal, project_id, state, receipt_sha=receipt_sha, kind=kind, buckets=buckets)
        if state
        else None
    )


def find_issued_export(journal, project_id, *, state, kind, selector):
    _, selector_sha = selector_ref(project_id, state, kind, selector)
    _, buckets = _index(journal, project_id)
    issuance = _lookup(journal, buckets, "selector:" + selector_sha)
    return (
        _read(journal, project_id, issuance, selector_sha=selector_sha, kind=kind, buckets=buckets)
        if issuance
        else None
    )


def issue_export(journal, *, project_id, actor_id, state, kind, payload=None, selector=None):
    """Server-derived inputs only; HTTP callers authorize their complete source state."""
    if kind not in SERIALIZERS:
        raise ValueError("Unsupported issued consumer export kind")
    selector = selector or {}
    source = product_state(journal, state, project_id)
    if state not in reachable_states(journal, project_id):
        raise ValueError("Issued inputs require a committed product history state")
    cached = find_issued_export(journal, project_id, state=state, kind=kind, selector=selector)
    if cached:
        if payload is not None and canonical(payload) != canonical(cached["payload"]):
            raise Conflict(
                "Issued selector already belongs to different serialized input; version the receipt contract"
            )
        return cached
    bundle, manifest = export_bytes(journal, state)
    payload, receipt, files = _inputs(
        kind, payload, bundle, manifest, project_id, source.version, state
    )
    receipt_sha = digest(canonical(receipt))
    _, selector_sha = selector_ref(project_id, state, kind, selector)
    if existing := resolve_issued_export(journal, project_id, receipt_sha):
        if existing["selector"] == selector and canonical(existing["payload"]) == canonical(
            payload
        ):
            return existing
        # A receipt omitting output-relevant options cannot safely identify two
        # different captures. Never alias a second selector or overwrite history.
        raise Conflict(
            "Native receipt already has a different issued selector; version the receipt contract"
        )
    artifacts = {
        name: {
            "sha256": journal.objects.put(raw),
            "bytes": len(raw),
            "media_type": "application/json",
        }
        for name, raw in files.items()
    }
    record = {
        "format": FORMAT,
        "kind": kind,
        "project_id": project_id,
        "version": source.version,
        "source_state": state,
        "receipt_sha256": receipt_sha,
        "files": artifacts,
        "selector": selector,
        "selector_sha256": selector_sha,
        "serializer_id": (
            "dtvp." + kind + "-serializer/3"
            if "pipeline_context" in json.loads(bundle)
            else "dtvp.knowledge-bundle-serializer/2"
            if kind == "knowledge-bundle" and "component_metadata" in payload
            else SERIALIZERS[kind]
        ),
        "material_fingerprint_id": MATERIAL_FORMAT,
        "material_fingerprint": material_fingerprint(journal, state),
        "issued_by": actor_id,
        "issued_at": datetime.now(UTC).isoformat(),
        "verification": "issued_artifact_scope_and_digest_consistency_only",
    }
    operation = {
        key: value for key, value in record.items() if key not in {"issued_by", "issued_at"}
    }
    sections = {name: {} for name in SECTIONS}
    sections["history"]["issued-export"] = record
    issuance = journal.snapshot(
        project_id=project_id,
        version="@export/" + receipt_sha,
        actor_id=actor_id,
        reason="Issue immutable native consumer inputs",
        sections=sections,
        parents=[state],
        artifacts=sorted({file["sha256"] for file in artifacts.values()}),
    )
    # One ref per project; immutable buckets shard lookup entries by SHA prefix.
    keys = ["receipt:" + receipt_sha, "selector:" + selector_sha]
    for _ in range(16):
        previous, buckets = _index(journal, project_id)
        existing = _lookup(journal, buckets, keys[0])
        if existing:
            captured = _read(
                journal, project_id, existing, receipt_sha=receipt_sha, buckets=buckets
            )
            if captured["selector"] != selector or canonical(captured["payload"]) != canonical(
                payload
            ):
                raise Conflict(
                    "Native receipt already has a different issued selector; version the receipt contract"
                )
            return captured
        if _lookup(journal, buckets, keys[1]):
            raise Conflict(
                "Issued selector already belongs to different serialized input; version the receipt contract"
            )
        changed = {}
        for key in keys:
            prefix = key.split(":", 1)[1][:2]
            if prefix not in changed:
                changed[prefix] = (
                    dict(journal.load(buckets[prefix])["entries"]) if prefix in buckets else {}
                )
            changed[prefix][key] = issuance
        updated = dict(buckets)
        for prefix, entries in changed.items():
            updated[prefix] = journal.store({"format": BUCKET_FORMAT, "entries": entries})
        sections = {name: {} for name in SECTIONS}
        sections["history"]["issued-export-index"] = {"format": INDEX_FORMAT, "buckets": updated}
        target = journal.snapshot(
            project_id=project_id,
            version="@export-index",
            actor_id=actor_id,
            reason="Index immutable consumer input capture",
            sections=sections,
            parents=([previous] if previous else []) + [issuance],
            artifacts=sorted(set(updated.values())),
        )
        try:
            journal.publish(
                request_id=digest(
                    canonical(["consumer-export.issue/2", project_id, receipt_sha, previous])
                ),
                fingerprint=digest(canonical(operation)),
                updates=[Update(ref=index_ref(project_id), expected=previous, target=target)],
            )
            return resolve_issued_export(journal, project_id, receipt_sha, kind=kind)
        except Conflict:
            continue
    raise Conflict("Concurrent consumer export issuance; retry unchanged input")
