"""Explicit external code-analysis evidence; consistency is never approval/authenticity."""

import copy
import math

from packageurl import PackageURL
from pydantic import Field

from dtvp.analysis import normalize
from dtvp.knowledge.agentyzer import AgentyzerSourceReceipt, derive_analysis_input
from dtvp.knowledge.assessments import target_fingerprint
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.workspace import load_sections
from dtvp.rescoring import base_fact, calculate
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_REPORT_BYTES = 8 * 1024 * 1024
FORMAT = "dtvp.code-analysis/1"
ENVELOPE = "dtvp.agentyzer-result-envelope/1"


class AgentyzerResultInput(RequestModel):
    request_id: Name
    expected: Sha
    input_receipt: AgentyzerSourceReceipt
    raw_report: dict
    source_label: Name = Field(default="Agentyzer")


def _json(value):
    pending, count = [(value, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 100000 or depth > 64:
            raise ValueError("Agentyzer report exceeds nesting/node limits")
        if isinstance(node, (dict, list)) and len(node) and (
            count + len(pending) + len(node) > 100000 or depth >= 64
        ):
            raise ValueError("Agentyzer report exceeds nesting/node limits")
        if isinstance(node, dict):
            if any(not isinstance(key, str) for key in node):
                raise ValueError("Agentyzer report keys must be strings")
            pending.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)
        elif node is not None and not isinstance(node, (str, int, float, bool)):
            raise ValueError("Agentyzer report must contain JSON values")
        elif isinstance(node, float) and not math.isfinite(node):
            raise ValueError("Agentyzer report numbers must be finite")
    raw = canonical(value)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Agentyzer report exceeds the 8 MiB intake limit")
    return raw


def _report(raw, derived):
    """Only the explicit native job+result envelope binds a structured advisory ID."""
    reasons = []
    if raw.get("format") == ENVELOPE:
        job, report = raw.get("job"), raw.get("report")
        if not isinstance(job, dict) or not isinstance(report, dict):
            return {}, ["malformed_native_result_envelope"]
        echoed, expected = job.get("request"), derived["request"]
        if (
            not isinstance(echoed, dict)
            or not expected
            or any(echoed.get(key) != value for key, value in (expected or {}).items())
        ):
            reasons.append("native_job_request_scope_mismatch")
        if (
            job.get("status") != "completed"
            or not isinstance(job.get("job_id"), str)
            or not job["job_id"]
        ):
            reasons.append("native_job_not_completed_or_identified")
    else:
        report = raw
        reasons.append("native_vulnerability_request_binding_missing")
    safe = copy.deepcopy(report)
    for key in ("assessment", "source_input"):
        if not isinstance(safe.get(key), dict):
            reasons.append("malformed_or_missing_" + key)
            safe[key] = {}
    assessment = safe["assessment"]
    for key in ("analysis", "summary", "reasoning", "verdict", "confidence"):
        if not isinstance(assessment.get(key), str):
            reasons.append("malformed_or_missing_" + key)
            assessment[key] = ""
    for key in ("version_analysis", "code_coverage"):
        if not isinstance(assessment.get(key), dict):
            reasons.append("malformed_or_missing_" + key)
            assessment[key] = {}
    version = assessment["version_analysis"]
    if not isinstance(version.get("comparison_inputs"), dict):
        reasons.append("malformed_or_missing_comparison_inputs")
        version["comparison_inputs"] = {}
    if assessment.get("adjusted_cvss") is not None and not isinstance(
        assessment["adjusted_cvss"], dict
    ):
        reasons.append("malformed_adjusted_cvss")
        assessment["adjusted_cvss"] = None
    steps = safe.get("steps")
    if not isinstance(steps, list) or any(
        not isinstance(step, dict)
        or not isinstance(step.get("findings"), dict)
        or not isinstance(step.get("evidence"), list)
        or any(not isinstance(value, str) for value in step.get("evidence", []))
        for step in steps
    ):
        reasons.append("malformed_or_missing_steps")
    return safe, reasons


def _candidate(report, sections, receipt, normalized):
    adjustment = report.get("assessment", {}).get("adjusted_cvss")
    if not isinstance(adjustment, dict):
        return None, ["native_scoring_vectors_unavailable"]
    original_score = adjustment.get("original_score")
    if isinstance(original_score, bool) or not isinstance(original_score, (int, float)):
        return None, ["native_original_score_missing_or_invalid"]
    fact = base_fact(adjustment.get("original_vector"), original_score)
    facts = [
        base_fact(rating.get("vector"), rating.get("score"))
        for claim in sections["vulnerabilities"].values()
        if claim.get("ref") == receipt["component_ref"]
        and claim.get("identifier") == receipt["vulnerability_id"]
        for rating in claim.get("advisory", {}).get("ratings", [])
        if isinstance(rating, dict)
    ]
    if not fact or fact not in facts:
        return None, ["original_base_not_in_pinned_source"]
    try:
        proposal = calculate(fact["vector"], adjustment.get("adjusted_vector"))
    except ValueError, TypeError, KeyError:
        return None, ["invalid_contextual_vector"]
    assessment = report["assessment"]
    reasons = []
    score = adjustment.get("adjusted_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or score != proposal["score"]:
        reasons.append("native_contextual_score_mismatch")
    if adjustment.get("version") is not None and adjustment["version"] != proposal["version"]:
        reasons.append("native_cvss_version_mismatch")
    if (
        assessment.get("cvss_vector") is not None
        and assessment["cvss_vector"] != proposal["vector"]
    ):
        reasons.append("native_assessment_vector_conflict")
    if assessment.get("cvss_score") is not None and (
        isinstance(assessment["cvss_score"], bool) or assessment["cvss_score"] != proposal["score"]
    ):
        reasons.append("native_assessment_score_conflict")
    if not normalized["rescoring_eligible"]:
        reasons.append("provider_rescoring_not_eligible")
    return proposal, reasons


def import_agentyzer_result(journal, *, project_id, version, actor_id, data):
    """Retain reports and optional vector proposals without modifying any human pins."""
    raw = _json(data.raw_report)
    payload = data.model_dump(mode="json")
    fingerprint = digest(
        canonical(["agentyzer.result.import/1", project_id, version, actor_id, payload])
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        replay = journal.receipt(request_id, fingerprint)
    if replay:
        return replay
    ref = Ref(project_id=project_id, name=version)
    if journal.resolve(ref) != data.expected:
        raise Conflict("Version changed; reload before importing code-analysis evidence")
    current = journal.state(data.expected)
    if current.project_id != project_id or current.version != version:
        raise Conflict("Expected state belongs to another product version")
    receipt = data.input_receipt.model_dump(mode="json")
    if receipt["project_id"] != project_id or receipt["version"] != version:
        raise ValueError("Agentyzer receipt belongs to another product version")
    if not journal.objects.path(receipt["state"]).is_file():
        raise ValueError("Agentyzer pinned input state is unavailable")
    from dtvp.knowledge.issued_exports import resolve_issued_export

    issued = resolve_issued_export(
        journal, project_id, digest(canonical(receipt)), kind="agentyzer-input"
    )
    derived = (
        issued["payload"]
        if issued
        else derive_analysis_input(
            journal, receipt["state"], receipt["context_id"], receipt["vulnerability_id"]
        )
    )
    if derived["receipt"] != receipt:
        raise ValueError("Agentyzer input receipt differs from reproduced pinned inputs")
    safe, reasons = _report(data.raw_report, derived)
    focal = receipt["focal_component"]
    qualified = receipt["analysis_source"] or {}
    name, group = focal.get("name"), focal.get("group")
    if not isinstance(name, str) or not name or (group is not None and not isinstance(group, str)):
        reasons.append("focal_package_identity_unknown")
        package = ""
    else:
        package = (group + "/" if group else "") + name
        if focal.get("purl"):
            try:
                parsed = PackageURL.from_string(focal["purl"])
                qualified_name = (parsed.namespace + "/" if parsed.namespace else "") + parsed.name
                if name not in {parsed.name, qualified_name} or (
                    group and group != parsed.namespace
                ):
                    reasons.append("focal_package_purl_name_conflict")
                if parsed.version and parsed.version != focal.get("version"):
                    reasons.append("focal_package_purl_version_conflict")
                package = qualified_name
            except ValueError, TypeError:
                reasons.append("focal_package_purl_invalid")
    normalized = normalize(
        safe if safe.get("assessment") is not None else {"assessment": {}},
        {
            "package_name": package,
            "version": focal.get("version"),
            "source_binding": {
                "status": "known" if qualified.get("source_commit") else "unknown",
                "source_commit": qualified.get("source_commit"),
            },
        },
    )
    normalized["source_commit_consistent"] = normalized.pop("source_verified")
    normalized["target_claim_consistent"] = normalized.pop("target_verified")
    if normalized["source_binding"]["status"] == "verified":
        normalized["source_binding"]["status"] = "receipt_consistent"
    reasons.extend(derived["coverage"]["reasons"])
    reasons.extend(normalized["ineligibility_reasons"])
    if normalized["proposal_state"] is None:
        reasons.append("no_definite_applicability_proposal")
    reasons = list(dict.fromkeys(reasons))
    source_sections = load_sections(journal, receipt["state"])
    proposal, score_reasons = _candidate(safe, source_sections, receipt, normalized)
    report_sha = journal.objects.put(raw)
    receipt_sha = journal.objects.put(canonical(receipt))
    identity = digest(
        canonical(
            ["agentyzer", data.source_label, report_sha, receipt_sha, actor_id, data.request_id]
        )
    )
    target = {
        "version": version,
        "context_id": receipt["context_id"],
        "vulnerability_id": receipt["vulnerability_id"],
    }
    sections = load_sections(journal, data.expected)
    record = {
        "format": FORMAT,
        "id": identity,
        "provider": "agentyzer",
        "kind": "code-analysis",
        "source_label": data.source_label,
        "imported_by": actor_id,
        "report_sha256": report_sha,
        "receipt_sha256": receipt_sha,
        "source_receipt": receipt,
        "source_fingerprint": receipt["assessment_fingerprint"],
        "target": target,
        "normalized": normalized,
        "source_blockers": reasons,
        "scoring_blockers": score_reasons,
        "proposal": proposal,
        "provider_claim": {
            key: data.raw_report.get("job", {}).get(key)
            for key in ("llm_provider", "llm_backend", "model")
        }
        if isinstance(data.raw_report.get("job"), dict)
        else {},
        "verification": "dtvp_pinned_receipt_and_report_claim_consistency_only",
        "provider_authenticity": "caller_asserted_not_verified",
        "job_report_association": "caller_asserted_not_verified",
        "repository_authorization": "not_checked",
        "build_binding_verified": False,
        "binary_binding_verified": False,
    }
    sections["history"]["code-analysis:" + identity] = record
    if proposal:
        sections["scoring"]["proposal:" + identity] = {
            **record,
            "format": "dtvp.scoring-proposal/1",
            "source_blockers": [*reasons, *score_reasons],
        }
    artifacts = set(current.artifacts) | {report_sha, receipt_sha}
    if receipt.get("sbom_sha256"):
        artifacts.add(receipt["sbom_sha256"])
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Import Agentyzer code-analysis evidence",
        sections=sections,
        parents=list(dict.fromkeys([data.expected, receipt["state"]])),
        artifacts=sorted(artifacts),
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=ref, expected=data.expected, target=state)],
    )


def list_agentyzer_results(
    journal, sections, version, context_id, vulnerability_id, *, fingerprint_resolver=None
):
    """Return comparable attributed proposals; stale evidence is always retained."""
    target = {"version": version, "context_id": context_id, "vulnerability_id": vulnerability_id}
    fingerprint = (
        fingerprint_resolver(context_id, vulnerability_id)
        if fingerprint_resolver
        else target_fingerprint(sections, version, context_id, vulnerability_id)
    )
    items = []
    for key, record in sorted(sections["history"].items()):
        if (
            not key.startswith("code-analysis:")
            or record.get("format") != FORMAT
            or record.get("target") != target
        ):
            continue
        current = bool(fingerprint and fingerprint == record["source_fingerprint"])
        reasons = list(record["source_blockers"])
        if not current:
            reasons.append(
                "source_target_absent" if fingerprint is None else "source_evidence_changed"
            )
        normalized = record["normalized"]
        eligible = bool(current and normalized["application_eligible"] and not reasons)
        scoring = bool(eligible and record["proposal"] and not record["scoring_blockers"])
        items.append(
            {
                **record,
                "current": current,
                "application_eligible": eligible,
                "rescoring_eligible": scoring,
                "ineligibility_reasons": reasons,
                "proposal_state": normalized["proposal_state"] if eligible else None,
                "rationale": normalized["rationale"],
                "summary": normalized["summary"],
                "confidence": normalized["confidence"],
                "verdict": normalized["verdict"],
                "source_proof": {
                    "source_binding": normalized["source_binding"],
                    "target_claim_consistent": normalized["target_claim_consistent"],
                    "source_commit_consistent": normalized["source_commit_consistent"],
                    "consistency_only": True,
                },
                "requires_human_assessment": True,
                "requires_coordinator_publication": True,
                "score_input": {
                    "targets": [target],
                    "base_vector": record["proposal"]["base_vector"],
                    "vector": record["proposal"]["vector"],
                }
                if scoring
                else None,
            }
        )
    return items
