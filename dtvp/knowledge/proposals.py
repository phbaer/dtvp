"""Imported contextual scoring proposals, separate from human publication."""

import re

from pydantic import Field

from dtvp.knowledge.assessments import target_fingerprint
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.vscorer import derive_context_inputs
from dtvp.knowledge.workspace import load_sections
from dtvp.rescoring import calculate
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_REPORT_BYTES = 8 * 1024 * 1024


class VScorerProposalInput(RequestModel):
    request_id: Name
    expected: Sha
    source_binding: dict
    finding: dict
    source_label: Name = Field(default="VScorer")


def _binding(journal, project_id, version, data):
    binding = data.source_binding
    receipt = binding.get("receipt")
    if not isinstance(receipt, dict):
        raise ValueError("VScorer requires its complete native source-binding receipt")
    if receipt.get("project_id") != project_id or receipt.get("version") != version:
        raise ValueError("VScorer source receipt belongs to another product version")
    if binding != {
        "receipt": receipt,
        "receipt_sha256": digest(canonical(receipt)),
        "verification": "artifact_scope_and_base_consistency",
        "remote_authenticity": "not_verified",
    }:
        raise ValueError("VScorer source-binding verification fields or receipt digest differ")
    for key in ("state", "context_id", "bundle_sha256"):
        value = receipt.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("VScorer source receipt requires exact content identifiers")
    for key in ("component_ref", "root_ref"):
        value = receipt.get(key)
        if not isinstance(value, str) or not 1 <= len(value) <= 1024:
            raise ValueError("VScorer source receipt requires bounded component references")
    selected = receipt.get("selected_source_base")
    if not isinstance(selected, dict) or not selected or len(selected) > 1000:
        raise ValueError(
            "VScorer source receipt requires bounded explicit original Base selections"
        )
    if not all(
        isinstance(value, dict) and isinstance(value.get("vector"), str)
        for value in selected.values()
    ):
        raise ValueError("VScorer source Base selections are malformed")
    if any(
        isinstance(value.get("score"), bool) or not isinstance(value.get("score"), (int, float))
        for value in selected.values()
    ):
        raise ValueError("VScorer original Base scores must be numbers")
    if not journal.objects.path(receipt["state"]).is_file():
        raise ValueError("VScorer pinned DTVP source state is unavailable")
    source = journal.verify_state(receipt.get("state"))
    if source.project_id != project_id or source.version != version:
        raise ValueError("VScorer pinned state belongs to another product version")
    from dtvp.knowledge.issued_exports import resolve_issued_export

    issued = resolve_issued_export(
        journal, project_id, binding["receipt_sha256"], kind="vscorer-input"
    )
    derived = (
        issued["payload"]
        if issued
        else derive_context_inputs(
            journal,
            receipt["state"],
            receipt.get("context_id"),
            receipt.get("component_ref"),
            {identifier: value["vector"] for identifier, value in selected.items()},
        )
    )
    if derived["dtvp_source"] != receipt:
        raise ValueError("VScorer source receipt differs from DTVP's pinned derived inputs")
    identifier = data.finding.get("cve_id")
    if not isinstance(identifier, str) or identifier not in selected:
        raise ValueError("VScorer result is outside its selected vulnerability scope")
    expected_fragment = {
        key: value for key, value in receipt.items() if key != "selected_source_base"
    } | {
        "selected_source_base": {identifier: selected[identifier]},
        "receipt_sha256": binding["receipt_sha256"],
        "verification": binding["verification"],
        "remote_authenticity": "not_verified",
    }
    facts = data.finding.get("source_facts")
    if not isinstance(facts, dict) or facts.get("dtvp_source") != expected_fragment:
        raise ValueError("VScorer finding does not echo the exact bound source context")
    if (
        isinstance(facts.get("base_score"), bool)
        or facts.get("base_vector") != selected[identifier]["vector"]
        or facts.get("base_score") != selected[identifier]["score"]
    ):
        raise ValueError("VScorer finding changed its original Base assertion")
    components = facts.get("components", [])
    if (
        not isinstance(components, list)
        or not all(isinstance(value, dict) for value in components)
        or [value.get("bom_ref") for value in components] != [receipt["component_ref"]]
    ):
        raise ValueError("VScorer finding changed its focused component scope")
    return receipt, identifier, derived


def _candidate(finding, base_vector):
    """Only a supported native draft preview can supply an adoptable proposal."""
    preview = finding.get("preview")
    if not isinstance(preview, dict):
        return None, ["native_preview_unavailable"]
    reasons = []
    if preview.get("environmental_approval_allowed") is not True or preview.get(
        "approval_blockers"
    ):
        reasons.append("native_preview_withheld")
    vector, score = preview.get("environmental_vector"), preview.get("environmental_score")
    try:
        proposal = calculate(base_vector, vector)
    except ValueError, TypeError, KeyError:
        return None, [*reasons, "invalid_contextual_vector"]
    if isinstance(score, bool) or not isinstance(score, (int, float)) or score != proposal["score"]:
        reasons.append("native_score_mismatch")
    return proposal, reasons


def import_vscorer_proposal(journal, *, project_id, version, actor_id, data):
    """Retain one explicitly imported report; never submit, approve or publish."""
    payload = data.model_dump(mode="json")
    raw = canonical({"source_binding": payload["source_binding"], "finding": payload["finding"]})
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("VScorer proposal report exceeds the 8 MiB intake limit")
    fingerprint = digest(
        canonical(["vscorer.proposal.import/1", project_id, version, actor_id, payload])
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        replay = journal.receipt(request_id, fingerprint)
    if replay:
        return replay
    ref = Ref(project_id=project_id, name=version)
    if journal.resolve(ref) != data.expected:
        raise Conflict("Version changed; reload before importing a scoring proposal")
    current = journal.state(data.expected)
    if current.project_id != project_id or current.version != version:
        raise Conflict("Expected state belongs to another product version")
    receipt, identifier, derived = _binding(journal, project_id, version, data)
    source_sections = load_sections(journal, receipt["state"])
    source_fingerprint = target_fingerprint(
        source_sections, version, receipt["context_id"], identifier
    )
    if source_fingerprint is None:
        raise ValueError("VScorer source target is absent from its pinned state")
    proposal, reasons = _candidate(
        data.finding, receipt["selected_source_base"][identifier]["vector"]
    )
    report_sha = journal.objects.put(raw)
    artifacts = {
        report_sha,
        journal.objects.put(canonical(receipt)),
        journal.objects.put(canonical(derived["sbom"])),
        journal.objects.put(canonical(derived["cves"])),
    }
    proposal_id = digest(
        canonical(["vscorer", data.source_label, report_sha, actor_id, request_id])
    )
    sections = load_sections(journal, data.expected)
    sections["scoring"]["proposal:" + proposal_id] = {
        "format": "dtvp.scoring-proposal/1",
        "id": proposal_id,
        "provider": "vscorer",
        "source_label": data.source_label,
        "imported_by": actor_id,
        "report_sha256": report_sha,
        "source_receipt": receipt,
        "receipt_sha256": data.source_binding["receipt_sha256"],
        "source_fingerprint": source_fingerprint,
        "target": {
            "version": version,
            "context_id": receipt["context_id"],
            "vulnerability_id": identifier,
        },
        "proposal": proposal,
        "source_blockers": reasons,
        "source_assessment_id": data.finding.get("assessment_id"),
        "source_finding_id": data.finding.get("id"),
        "verification": "dtvp_pinned_inputs_reproduced",
        "provider_authenticity": "caller_asserted_not_verified",
    }
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Import VScorer contextual scoring proposal",
        sections=sections,
        parents=list(dict.fromkeys([data.expected, receipt["state"]])),
        artifacts=sorted(set(current.artifacts) | artifacts),
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=ref, expected=data.expected, target=state)],
    )


def list_proposals(journal, sections, version, context_id, vulnerability_id):
    """Compare normalized proposals; eligibility never bypasses coordinator gates."""
    fingerprint = target_fingerprint(sections, version, context_id, vulnerability_id)
    items = []
    for key, record in sorted(sections["scoring"].items()):
        if not key.startswith("proposal:") or record.get("format") != "dtvp.scoring-proposal/1":
            continue
        if record.get("target") != {
            "version": version,
            "context_id": context_id,
            "vulnerability_id": vulnerability_id,
        }:
            continue
        reasons = list(record["source_blockers"])
        current = bool(fingerprint and fingerprint == record["source_fingerprint"])
        if not current:
            reasons.append(
                "source_target_absent" if fingerprint is None else "source_evidence_changed"
            )
        proposal = record["proposal"]
        items.append(
            {
                **record,
                "current": current,
                "eligible": bool(proposal and not reasons),
                "ineligibility_reasons": reasons,
                "requires_coordinator_publication": True,
                "score_input": {
                    "targets": [record["target"]],
                    "base_vector": proposal["base_vector"],
                    "vector": proposal["vector"],
                }
                if proposal and not reasons
                else None,
            }
        )
    return items
