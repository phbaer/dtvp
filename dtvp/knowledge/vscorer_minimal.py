"""Operator-bound proposals from the minimal VScorer REST contract.

This adapter never pretends VScorer echoed a DTVP receipt. Supplied exchange
association is an operator declaration, separately retained from provider facts.
"""

import csv
import io
import json
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from dtvp.knowledge.assessments import target_fingerprint
from dtvp.knowledge.evidence_conformance import bounded_tree
from dtvp.knowledge.issued_exports import resolve_issued_export
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.proposals import MAX_REPORT_BYTES, _candidate
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class UploadedInput(RequestModel):
    artifact_id: str = Field(min_length=1, max_length=32)
    sha256: Sha


class MinimalInputArtifacts(RequestModel):
    sbom: UploadedInput
    cves: UploadedInput
    items_csv: UploadedInput | None = None
    threat_model: UploadedInput | None = None


class MinimalMappingSelection(RequestModel):
    issued_input_receipt_sha256: Sha
    model_id: Name
    model_revision: Name
    model_sha256: Sha


class VScorerMinimalProposalInput(RequestModel):
    request_id: Name
    expected: Sha
    issued_input_receipt_sha256: Sha
    input_artifacts: MinimalInputArtifacts
    mapping_mode: Literal["not_declared", "issued_items_csv"]
    mapping_selection: MinimalMappingSelection | None = None
    assessment_id: str = Field(min_length=1, max_length=32)
    finding_json: Annotated[str, StringConstraints(strip_whitespace=False)] = Field(
        min_length=1, max_length=MAX_REPORT_BYTES
    )
    finding_sha256: Sha
    binding_reason: str = Field(min_length=1, max_length=6000)
    source_label: Name = "VScorer minimal"


def _reject_constant(value):
    raise ValueError("Nonfinite number in minimal VScorer result")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate member in minimal VScorer result")
        result[key] = value
    return result


def import_minimal_proposal(journal, *, project_id, version, actor_id, data):
    raw = data.finding_json.encode()
    if len(raw) > MAX_REPORT_BYTES or digest(raw) != data.finding_sha256:
        raise ValueError("Minimal VScorer result differs from its exact byte pin")
    if not data.binding_reason.strip():
        raise ValueError("Minimal VScorer requires an explicit operator binding reason")
    try:
        finding = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        bounded_tree(finding)
    except RecursionError:
        raise ValueError("Minimal VScorer result exceeds nesting bounds") from None
    if not isinstance(finding, dict):
        raise ValueError("Minimal VScorer finding must be an object")
    if (
        finding.get("assessment_id") != data.assessment_id
        or not isinstance(finding.get("id"), str)
        or not 1 <= len(finding["id"]) <= 32
    ):
        raise ValueError("Minimal VScorer finding assessment/id differs from operator scope")
    facts = finding.get("source_facts")
    if not isinstance(facts, dict) or "dtvp_source" in facts:
        raise ValueError(
            "Minimal VScorer requires native source facts without an invented DTVP receipt"
        )
    payload = data.model_dump(mode="json")
    fingerprint = digest(
        canonical(["vscorer.minimal-proposal.import/1", project_id, version, actor_id, payload])
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        replay = journal.receipt(request_id, fingerprint)
    if replay:
        return replay
    ref = Ref(project_id=project_id, name=version)
    if journal.resolve(ref) != data.expected:
        raise Conflict("Version changed; reload before importing minimal VScorer proposal")
    current = journal.state(data.expected)
    if current.project_id != project_id or current.version != version:
        raise Conflict("Expected state belongs to another product version")
    issued = resolve_issued_export(
        journal, project_id, data.issued_input_receipt_sha256, kind="vscorer-input"
    )
    if not issued or issued["version"] != version:
        raise ValueError(
            "Minimal VScorer requires previously issued inputs for this product version"
        )
    derived = issued["payload"]
    receipt = derived["dtvp_source"]
    for kind, uploaded in (
        ("sbom", data.input_artifacts.sbom),
        ("cves", data.input_artifacts.cves),
    ):
        if uploaded.sha256 != issued["files"][kind + ".json"]["sha256"]:
            raise ValueError("Minimal VScorer uploaded input hash differs from issued exact bytes")
    if data.input_artifacts.sbom.artifact_id == data.input_artifacts.cves.artifact_id:
        raise ValueError("Minimal VScorer upload IDs must distinguish SBOM and CVE artifacts")
    if data.mapping_mode == "issued_items_csv":
        if (
            data.mapping_selection is None
            or data.mapping_selection.issued_input_receipt_sha256
            != data.issued_input_receipt_sha256
            or data.input_artifacts.items_csv is None
            or data.input_artifacts.threat_model is None
        ):
            raise ValueError(
                "Minimal VScorer mapping needs exact issued selection, items.csv and TM7 upload pins"
            )
        mapping_report = derive_minimal_mapping(
            journal, project_id=project_id, data=data.mapping_selection
        )
        if (
            data.input_artifacts.items_csv.sha256 != mapping_report["items_csv_sha256"]
            or data.input_artifacts.threat_model.sha256 != data.mapping_selection.model_sha256
        ):
            raise ValueError(
                "Minimal VScorer items.csv or TM7 hash differs from declared model inputs"
            )
    else:
        if (
            data.mapping_selection is not None
            or data.input_artifacts.items_csv is not None
            or data.input_artifacts.threat_model is not None
        ):
            raise ValueError("Undeclared mapping mode cannot imply an items.csv binding")
        mapping_report = None
    identifier = finding.get("cve_id")
    selected = receipt.get("selected_source_base", {})
    if not isinstance(identifier, str) or identifier not in selected:
        raise ValueError("Minimal VScorer CVE is outside the issued context selection")
    original = selected[identifier]
    native_components = [
        derived["sbom"].get("metadata", {}).get("component", {}),
        *derived["sbom"].get("components", []),
    ]
    source_component = next(
        (item for item in native_components if item.get("bom-ref") == receipt["component_ref"]),
        None,
    )
    if source_component is None:
        raise ValueError("Minimal VScorer focused occurrence is absent from issued SBOM")
    components = facts.get("components")
    if (
        not isinstance(components, list)
        or len(components) != 1
        or not isinstance(components[0], dict)
        or components[0].get("bom_ref") != receipt["component_ref"]
    ):
        raise ValueError("Minimal VScorer component occurrence differs from issued scope")
    if (
        facts.get("cve_id", identifier) != identifier
        or facts.get("base_vector") != original["vector"]
        or isinstance(facts.get("base_score"), bool)
        or facts.get("base_score") != original["score"]
    ):
        raise ValueError("Minimal VScorer changed its original CVE/Base assertion")
    if any(
        components[0].get(key) != source_component.get(key, "")
        for key in ("name", "version", "purl")
    ):
        raise ValueError("Minimal VScorer component facts differ from issued exact SBOM")
    proposal, reasons = _candidate(finding, original["vector"])
    preview = finding.get("preview")
    if isinstance(preview, dict) and (
        preview.get("finding_id") != finding["id"]
        or type(finding.get("version")) is not int
        or type(preview.get("finding_version")) is not int
        or preview.get("finding_version") != finding["version"]
    ):
        raise ValueError("Minimal VScorer preview is not bound to the same finding revision")
    if not isinstance(preview, dict) or preview.get("scope_complete") is not True:
        reasons.append("minimal_provider_scope_incomplete")
    for key in ("base_conflict", "component_scope_conflict", "unresolved_scope"):
        if facts.get(key) is not False:
            reasons.append("minimal_provider_" + key + "_not_cleared")
    source_sections = load_sections(journal, receipt["state"])
    source_fingerprint = target_fingerprint(
        source_sections, version, receipt["context_id"], identifier
    )
    if source_fingerprint is None:
        raise ValueError("Minimal VScorer issued target is absent from its pinned state")
    report_sha = journal.objects.put(raw)
    exchange_sha = journal.objects.put(canonical(payload))
    mapping_report_sha = journal.objects.put(canonical(mapping_report)) if mapping_report else None
    mapping_csv_sha = (
        journal.objects.put(mapping_report["items_csv"].encode()) if mapping_report else None
    )
    proposal_id = digest(canonical(["vscorer-minimal", actor_id, request_id, report_sha]))
    sections = load_sections(journal, data.expected)
    sections["scoring"]["proposal:" + proposal_id] = {
        "format": "dtvp.scoring-proposal/1",
        "id": proposal_id,
        "provider": "vscorer",
        "source_label": data.source_label,
        "imported_by": actor_id,
        "report_sha256": report_sha,
        "exchange_sha256": exchange_sha,
        "source_receipt": receipt,
        "receipt_sha256": data.issued_input_receipt_sha256,
        "source_fingerprint": source_fingerprint,
        "target": {
            "version": version,
            "context_id": receipt["context_id"],
            "vulnerability_id": identifier,
        },
        "proposal": proposal,
        "source_blockers": reasons,
        "source_assessment_id": data.assessment_id,
        "source_finding_id": finding["id"],
        "verification": "operator_bound_minimal_rest_exchange",
        "provider_authenticity": "caller_asserted_not_verified",
        "binding_origin": "DTVP operator; not echoed by VScorer",
        "binding_reason": data.binding_reason,
        "mapping_mode": data.mapping_mode,
        "mapping_report_digest": mapping_report["report_digest"] if mapping_report else None,
        "mapping_report_sha256": mapping_report_sha,
        "mapping_csv_sha256": mapping_csv_sha,
        "input_declarations": data.input_artifacts.model_dump(mode="json"),
        "limitations": [
            "Upload/assessment/result association is an operator declaration, not provider-authenticated provenance.",
            "No threat-model authenticity, mapping approval, human assessment or score publication is established.",
            "Threat-model upload associations are operator declarations; effective VScorer settings and configuration content are not verified.",
        ],
    }
    artifacts = {report_sha, exchange_sha, journal.objects.put(canonical(receipt))}
    artifacts.update(item["sha256"] for item in issued["files"].values())
    if mapping_report_sha and mapping_csv_sha:
        artifacts.update([mapping_report_sha, mapping_csv_sha])
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Import operator-bound minimal VScorer proposal",
        sections=sections,
        parents=list(dict.fromkeys([data.expected, receipt["state"]])),
        artifacts=sorted(set(current.artifacts) | artifacts),
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=ref, expected=data.expected, target=state)],
    )


def derive_minimal_mapping(journal, *, project_id, data):
    """Convert one issued contextual model declaration to canonical minimal items.csv."""
    issued = resolve_issued_export(
        journal, project_id, data.issued_input_receipt_sha256, kind="vscorer-input"
    )
    if not issued:
        raise ValueError("Minimal mapping requires previously issued VScorer inputs")
    payload = issued["payload"]
    receipt = payload["dtvp_source"]
    context = payload.get("pipeline_context")
    if (
        not isinstance(context, dict)
        or context.get("context_id") != receipt["context_id"]
        or context.get("inventory_state") != receipt["state"]
    ):
        raise ValueError("Issued inputs lack an exact pinned contextual model declaration")
    models = [
        model for model in context.get("models", []) if model.get("model_id") == data.model_id
    ]
    if (
        len(models) != 1
        or models[0].get("revision") != data.model_revision
        or models[0].get("digest_sha256") != data.model_sha256
    ):
        raise ValueError("Selected model differs from the exact issued revision/digest")
    model = models[0]
    known_entities = {entity["entity_id"] for entity in model["entities"]}
    rows = context.get("rows", [])
    if len(rows) != 1 or any(
        row.get("context_id") != receipt["context_id"]
        or row.get("component_ref") != receipt["component_ref"]
        or row.get("root_ref") != receipt["root_ref"]
        for row in rows
    ):
        raise ValueError("Minimal mapping input spans ambiguous or different consuming contexts")
    pairs = set()
    for row in rows:
        for mapping in row.get("mappings", []):
            if mapping.get("model_id") != data.model_id:
                continue
            if (
                mapping.get("model_revision") != data.model_revision
                or mapping.get("model_sha256") != data.model_sha256
                or not set(mapping.get("entity_ids", [])) <= known_entities
            ):
                raise ValueError("Issued mapping does not match its pinned model entities")
            pairs.update((row["component_ref"], entity) for entity in mapping.get("entity_ids", []))
    if not pairs or len(pairs) > 100000:
        raise ValueError("No bounded explicit mappings exist for the selected issued model")
    text = io.StringIO(newline="")
    writer = csv.writer(text, delimiter=";", lineterminator="\n")
    writer.writerow(["component_ref", "threat_model_element_id"])
    writer.writerows(sorted(pairs))
    raw = text.getvalue().encode()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Minimal items.csv exceeds 2 MiB")
    content = {
        "format": "dtvp.vscorer-minimal-mapping/1",
        "committed": False,
        "project_id": project_id,
        "version": receipt["version"],
        "state": receipt["state"],
        "context_id": receipt["context_id"],
        "issued_input_receipt_sha256": data.issued_input_receipt_sha256,
        "model_id": data.model_id,
        "model_revision": data.model_revision,
        "model_sha256": data.model_sha256,
        "configuration_state": context["configuration_state"],
        "filename": "items.csv",
        "items_csv": text.getvalue(),
        "items_csv_sha256": digest(raw),
        "mapping_rows": len(pairs),
        "assurance": "CI_or_operator_declared_placements_not_authenticated",
        "limitations": [
            "No threat model is invented or fetched; model/placement declarations require independent consumer validation.",
            "Uploading this items.csv and selecting its effective VScorer settings are separate explicit external actions.",
            "No mapping approval, source authenticity, score change or human assessment is established.",
        ],
    }
    return {**content, "report_digest": digest(canonical(content))}
