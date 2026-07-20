from __future__ import annotations

import hashlib
import re
from typing import Any

from ..code_analysis_assessment_services import (
    discover_assessment_metadata,
    lower as _lower,
    mapping as _mapping,
    record_assessment as _record_assessment,
    record_context_summary as _record_context_summary,
    record_project_names as _record_project_names,
    record_result as _record_result,
    record_run_id as _record_run_id,
    record_target as _record_target,
    record_vulnerability_id as _record_vulnerability_id,
    text as _text,
)
from .assessment_restore import selected_groups
from .base import BulkWorkflowContext, BulkWorkflowPlugin


VERDICT_PRIORITY = {
    "NOT_AFFECTED": 0,
    "INCONCLUSIVE": 1,
    "PROBABLY_AFFECTED": 2,
    "AFFECTED": 3,
}

def _instances(group: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        component
        for version in (group.get("affected_versions") or [])
        for component in (version.get("components") or [])
        if isinstance(component, dict)
    ]


def _group_vulnerability_ids(group: dict[str, Any]) -> set[str]:
    return {
        normalized
        for value in [group.get("id"), *(group.get("aliases") or [])]
        if (normalized := _lower(value))
    }


def normalize_verdict(assessment: dict[str, Any]) -> str:
    verdict = _lower(assessment.get("verdict")).replace("_", " ").replace("-", " ")
    if "not affected" in verdict or verdict in {"unaffected", "safe"}:
        return "NOT_AFFECTED"
    if "probably affected" in verdict or "likely affected" in verdict:
        return "PROBABLY_AFFECTED"
    if verdict == "affected" or assessment.get("affected") is True:
        return "AFFECTED"
    analysis = _lower(assessment.get("analysis")).replace("_", " ").replace("-", " ")
    if analysis in {"not affected", "false positive"}:
        return "NOT_AFFECTED"
    if analysis in {"affected", "exploitable"}:
        return "AFFECTED"
    return "INCONCLUSIVE"


def verdict_state(verdict: str) -> str:
    if verdict == "AFFECTED":
        return "EXPLOITABLE"
    if verdict == "NOT_AFFECTED":
        return "NOT_AFFECTED"
    return "IN_TRIAGE"


def _group_project_names(group: dict[str, Any]) -> set[str]:
    return {
        name
        for instance in _instances(group)
        if (name := _lower(instance.get("project_name")))
    }


def _records_for_group(
    group: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    vulnerability_ids = _group_vulnerability_ids(group)
    project_names = _group_project_names(group)
    matched: list[dict[str, Any]] = []
    for record in records:
        if _record_vulnerability_id(record) not in vulnerability_ids:
            continue
        record_projects = _record_project_names(record)
        if (
            project_names
            and record_projects
            and project_names.isdisjoint(record_projects)
        ):
            continue
        matched.append(record)
    return matched


def _records_by_vulnerability(
    records: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        vulnerability_id = _record_vulnerability_id(record)
        if vulnerability_id:
            index.setdefault(vulnerability_id, []).append(record)
    return index


def _matched_records_for_group(
    group: dict[str, Any],
    index: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen_run_ids: set[str] = set()
    for vulnerability_id in sorted(_group_vulnerability_ids(group)):
        for record in index.get(vulnerability_id, []):
            run_id = _record_run_id(record)
            if run_id in seen_run_ids:
                continue
            seen_run_ids.add(run_id)
            candidates.append(record)
    return sorted(
        _records_for_group(group, candidates),
        key=_record_run_id,
    )


def _unique_records(
    group_records: list[tuple[dict[str, Any], list[dict[str, Any]]]],
) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for _group, records in group_records:
        for record in records:
            run_id = _record_run_id(record)
            if run_id:
                unique.setdefault(run_id, record)
    return list(unique.values())


def _latest_assessment_records(
    context: BulkWorkflowContext,
    diagnostics: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    if context.assessment_records is not None:
        if diagnostics is not None:
            diagnostics.update(context.assessment_diagnostics)
        return context.assessment_records
    return discover_assessment_metadata(context.result_store, diagnostics)


def _hydrate_records(
    context: BulkWorkflowContext,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Load full analysis payloads only for records selected for apply/export."""
    run_ids = list(
        dict.fromkeys(
            run_id
            for record in records
            if (run_id := _record_run_id(record))
        )
    )
    if not run_ids or context.result_store is None:
        return records
    if hasattr(context.result_store, "get_many"):
        loaded = context.result_store.get_many(run_ids)
    elif hasattr(context.result_store, "get"):
        loaded = [
            record
            for run_id in run_ids
            if (record := context.result_store.get(run_id)) is not None
        ]
    else:
        return records
    loaded_by_id = {
        run_id: record
        for record in loaded
        if (run_id := _record_run_id(record))
    }
    return [loaded_by_id.get(_record_run_id(record), record) for record in records]


def _selected_group_records(
    context: BulkWorkflowContext,
    group_ids: list[str],
) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    metadata = _latest_assessment_records(context)
    metadata_index = _records_by_vulnerability(metadata)
    metadata_pairs = [
        (group, _matched_records_for_group(group, metadata_index))
        for group in selected_groups(context.groups, group_ids)
    ]
    hydrated = _hydrate_records(context, _unique_records(metadata_pairs))
    hydrated_index = _records_by_vulnerability(hydrated)
    return [
        (group, _matched_records_for_group(group, hydrated_index))
        for group, _metadata_records in metadata_pairs
    ]


def _application_keys(
    context: BulkWorkflowContext,
    records: list[dict[str, Any]],
) -> set[tuple[str, str]]:
    if context.result_store is None:
        return set()
    run_ids = [_record_run_id(record) for record in records]
    return {
        (
            _text(application.get("analysis_run_id")),
            _text(application.get("finding_uuid")),
        )
        for application in context.result_store.list_applications(
            analysis_run_ids=run_ids,
            statuses=["applied", "queued"],
        )
    }


def _application_finding_key(instance: dict[str, Any]) -> str:
    finding_uuid = _text(instance.get("finding_uuid"))
    if finding_uuid:
        return finding_uuid
    identity = [
        _text(instance.get(key))
        for key in ("project_uuid", "component_uuid", "vulnerability_uuid")
    ]
    if not all(identity):
        return ""
    return "finding:" + ":".join(identity)


def _boolean_text(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return ""


def _text_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    values = sorted(value, key=str) if isinstance(value, set) else value
    return list(
        dict.fromkeys(
            _text(item)
            for item in values
            if item is not None and not isinstance(item, (dict, list, tuple, set))
            and _text(item)
        )
    )


def _append_section(
    lines: list[str],
    seen_values: set[str],
    title: str,
    paragraphs: list[str] | None = None,
    bullets: list[str] | None = None,
) -> None:
    section_paragraphs: list[str] = []
    section_bullets: list[str] = []
    for target, values in (
        (section_paragraphs, paragraphs or []),
        (section_bullets, bullets or []),
    ):
        for value in values:
            rendered = _text(value)
            signature = rendered.casefold()
            if not rendered or signature in seen_values:
                continue
            seen_values.add(signature)
            target.append(rendered)
    if not section_paragraphs and not section_bullets:
        return
    lines.extend(["", f"{title}:", *section_paragraphs])
    lines.extend(f"  - {value}" for value in section_bullets)


def _is_generated_report(value: Any) -> bool:
    return "VULNERABILITY ASSESSMENT REPORT" in _text(value).upper()


def _has_semantic_narrative(assessment: dict[str, Any]) -> bool:
    return bool(
        _text(assessment.get("summary"))
        or _text(assessment.get("reasoning"))
        or assessment.get("researcher_view")
        or assessment.get("remediation_view")
        or assessment.get("audit_view")
    )


def _assessment_content_lines(
    assessment: dict[str, Any],
    seen_values: set[str],
) -> list[str]:
    lines: list[str] = []
    _append_section(
        lines,
        seen_values,
        "Summary",
        [_text(assessment.get("summary"))],
    )
    _append_section(
        lines,
        seen_values,
        "Rationale",
        [_text(assessment.get("reasoning"))],
    )

    mapping_facts = [
        f"Affected: {_boolean_text(assessment.get('affected'))}"
        if isinstance(assessment.get("affected"), bool)
        else "",
        f"Analyzer state: {_text(assessment.get('analysis'))}"
        if _text(assessment.get("analysis"))
        else "",
        f"Analyzer justification: {_text(assessment.get('justification'))}"
        if _text(assessment.get("justification"))
        else "",
        f"Suggested response: {_text(assessment.get('response'))}"
        if _text(assessment.get("response"))
        else "",
    ]
    _append_section(lines, seen_values, "Assessment mapping", bullets=mapping_facts)

    dependency = assessment.get("dependency_presence")
    if isinstance(dependency, dict):
        basis = _text(dependency.get("presence_basis"))
        if basis == "direct":
            presence = "Found as a direct dependency."
        elif basis == "transitive":
            presence = "Found as a transitive dependency."
        elif basis == "sbom_attributed" or dependency.get("sbom_attributed") is True:
            presence = (
                "Present via SBOM attribution; not rediscovered in repository "
                "manifests or lock files."
            )
        elif dependency.get("found") is False:
            presence = "The vulnerable component was not found in the assessed project."
        elif dependency.get("found") is True:
            presence = "The vulnerable component is present in the assessed project."
        else:
            presence = ""
        dependency_facts = []
        if locked_version := _text(dependency.get("locked_version")):
            dependency_facts.append(f"Resolved version: {locked_version}")
        dependency_facts.extend(
            f"Declared in: {path}"
            for path in _text_list(dependency.get("declared_in"))
        )
        _append_section(
            lines,
            seen_values,
            "Dependency evidence",
            [presence],
            dependency_facts,
        )

    advisory = assessment.get("advisory_relevance")
    if isinstance(advisory, dict):
        status_parts = []
        if relevant := _boolean_text(advisory.get("relevant")):
            status_parts.append(f"Relevant: {relevant}")
        if applies := _boolean_text(advisory.get("applies_to_detected_version")):
            status_parts.append(f"Applies to detected version: {applies}")
        if status := _text(advisory.get("status")):
            status_parts.append(f"Status: {status}")
        if source := _text(advisory.get("source")):
            status_parts.append(f"Source: {source}")
        _append_section(
            lines,
            seen_values,
            "Advisory relevance",
            ["; ".join(status_parts)],
            _text_list(advisory.get("reasons")),
        )

    version = assessment.get("version_analysis")
    if isinstance(version, dict):
        status_parts = []
        if detected := _text(version.get("detected_version")):
            status_parts.append(f"Detected version: {detected}")
        if source := _text(version.get("version_source")):
            status_parts.append(f"Source: {source}")
        if affected := _boolean_text(version.get("affected")):
            status_parts.append(f"Affected releases found: {affected}")
        if workspace_affected := _boolean_text(
            version.get("current_workspace_affected")
        ):
            status_parts.append(f"Current workspace affected: {workspace_affected}")
        product_versions = _text_list(version.get("affected_product_versions"))
        _append_section(
            lines,
            seen_values,
            "Version evidence",
            [
                "; ".join(status_parts),
                _text(version.get("note")),
                _text(version.get("workspace_note")),
            ],
            [f"Affected product versions: {', '.join(product_versions)}"]
            if product_versions
            else [],
        )

    researcher = assessment.get("researcher_view")
    if isinstance(researcher, dict):
        conclusion = _text(researcher.get("conclusion"))
        _append_section(
            lines,
            seen_values,
            "Research conclusion",
            [conclusion],
            _text_list(researcher.get("findings")),
        )

    remediation = assessment.get("remediation_view")
    if isinstance(remediation, dict):
        status = _text(remediation.get("status"))
        _append_section(
            lines,
            seen_values,
            "Remediation",
            [
                f"Status: {status}" if status else "",
                _text(remediation.get("summary")),
            ],
            _text_list(remediation.get("recommendations")),
        )

    audit = assessment.get("audit_view")
    if isinstance(audit, dict):
        audit_status = []
        if status := _text(audit.get("status")):
            audit_status.append(f"Status: {status}")
        if consistency := _text(audit.get("consistency")):
            audit_status.append(f"Consistency: {consistency}")
        _append_section(
            lines,
            seen_values,
            "Audit conclusion",
            ["; ".join(audit_status), _text(audit.get("conclusion"))],
            _text_list(audit.get("checks")),
        )

    details = assessment.get("details")
    if details and (
        not _is_generated_report(details) or not _has_semantic_narrative(assessment)
    ):
        _append_section(
            lines,
            seen_values,
            "Additional analysis",
            [_text(details)],
        )
    return lines


def _assessment_record_lines(
    record: dict[str, Any],
    assessment: dict[str, Any],
) -> list[str]:
    run_id = _record_run_id(record) or "Unknown"
    context_summary = _record_context_summary(record)
    target = _record_target(record)
    result = _record_result(record)
    project = (
        _text(record.get("project_name"))
        or _text(context_summary.get("project_name"))
        or _text(target.get("project_name"))
        or "Unknown"
    )
    component = (
        _text(record.get("component_name"))
        or _text(context_summary.get("target_component"))
        or _text(target.get("component_name"))
        or "Unknown"
    )
    lines = [
        f"[Automatic Assessment: {run_id}]",
        f"Project: {project}",
        f"Component: {component}",
        f"Verdict: {_text(assessment.get('verdict')) or 'Inconclusive'}",
        f"Confidence: {_text(assessment.get('confidence')) or 'unknown'}",
        f"Exposure: {_text(assessment.get('exposure')) or 'unknown'}",
    ]
    seen_values: set[str] = set()
    lines.append(f"Run Source: {_text(record.get('source')) or 'legacy'}")
    if target_team := _text(context_summary.get("target_team")):
        lines.append(f"Target Team: {target_team}")

    adjusted_cvss = assessment.get("adjusted_cvss")
    if isinstance(adjusted_cvss, dict):
        if adjusted_cvss.get("adjusted_score") is not None:
            lines.append(f"[Rescored: {float(adjusted_cvss['adjusted_score']):.1f}]")
        if _text(adjusted_cvss.get("adjusted_vector")):
            lines.append(
                f"[Rescored Vector: {_text(adjusted_cvss.get('adjusted_vector'))}]"
            )
        original_score = adjusted_cvss.get("original_score")
        adjusted_score = adjusted_cvss.get("adjusted_score")
        if original_score is not None and adjusted_score is not None:
            lines.append(
                f"CVSS: {float(original_score):.1f} -> {float(adjusted_score):.1f}"
            )
        _append_section(
            lines,
            seen_values,
            "CVSS rationale",
            [_text(adjusted_cvss.get("summary"))],
            _text_list(adjusted_cvss.get("reasons")),
        )

    lines.extend(_assessment_content_lines(assessment, seen_values))

    advisory_sources = _text_list(assessment.get("advisory_sources"))
    if advisory_sources:
        lines.extend(["", "Advisory sources:"])
        lines.extend(f"  - {source}" for source in advisory_sources)
    cwe_ids = _text_list(assessment.get("cwe_ids"))
    cwe_descriptions = assessment.get("cwe_descriptions")
    if cwe_ids or isinstance(cwe_descriptions, dict):
        cwes = [
            f"{cwe_id}: {_text(cwe_descriptions.get(cwe_id))}"
            if isinstance(cwe_descriptions, dict) and cwe_descriptions.get(cwe_id)
            else cwe_id
            for cwe_id in cwe_ids
        ]
        if isinstance(cwe_descriptions, dict):
            cwes.extend(
                f"{cwe_id}: {_text(description)}"
                for cwe_id, description in cwe_descriptions.items()
                if cwe_id not in cwe_ids and _text(description)
            )
        lines.extend(["", "Weaknesses:"])
        lines.extend(f"  - {cwe}" for cwe in dict.fromkeys(cwes))

    summary = _mapping(record.get("summary"))
    versions = _text_list(
        result.get("versions_checked") or summary.get("versions_checked")
    )
    if versions:
        lines.extend(["", "Versions Checked:"])
        lines.extend(f"  - {version}" for version in versions)

    component_results = result.get("component_results") or summary.get(
        "component_results"
    )
    if isinstance(component_results, list):
        for component_result in component_results:
            if not isinstance(component_result, dict):
                continue
            component_assessment = _mapping(component_result.get("assessment"))
            lines.extend(
                [
                    "",
                    f"[Component: {_text(component_result.get('component')) or 'Unknown'}]",
                ]
            )
            lines.extend(_assessment_content_lines(component_assessment, seen_values))
    return lines


def _assessment_details(
    entries: list[dict[str, Any]],
    *,
    verdict: str,
    state: str,
    justification: str,
) -> str:
    run_ids = sorted(
        {
            run_id
            for entry in entries
            if (run_id := _record_run_id(entry["record"]))
        }
    )
    header = (
        f"--- [Team: General] [State: {state}] "
        f"[Assessed By: Automated Code Analysis] [Justification: {justification}] "
        f"[Evidence Reviewed: yes] [Analysis Runs: {', '.join(run_ids)}] ---"
    )
    lines = [
        header,
        "[Code Analysis]",
        f"Overall Verdict: {verdict.replace('_', ' ').title()}",
        f"Overall Assessment State: {state}",
        f"Automatic Assessment Count: {len(entries)}",
    ]
    for entry in entries:
        lines.extend(["", *_assessment_record_lines(entry["record"], entry["assessment"])])
    return "\n".join(lines)


def _ticket_text(group: dict[str, Any], entries: list[dict[str, Any]]) -> str:
    affected_entries = [
        entry
        for entry in entries
        if entry["verdict_bucket"]
        in {"AFFECTED", "PROBABLY_AFFECTED", "INCONCLUSIVE"}
    ]
    if not affected_entries:
        return ""
    supplied = list(dict.fromkeys([
        _text(entry["assessment"].get("ticket_text"))
        for entry in affected_entries
        if _text(entry["assessment"].get("ticket_text"))
    ]))
    if supplied:
        return "\n\n---\n\n".join(supplied)
    components = sorted(
        {_text(entry["record"].get("component_name")) for entry in affected_entries}
    )
    projects = sorted({_text(entry["record"].get("project_name")) for entry in affected_entries})
    verdicts = ", ".join(
        f"{_text(entry['record'].get('component_name'))}: "
        f"{_text(entry['assessment'].get('verdict')) or 'Inconclusive'}"
        for entry in affected_entries
    )
    run_ids = ", ".join(
        _record_run_id(entry["record"])
        for entry in affected_entries
    )
    group_id = _text(group.get("id"))
    return "\n".join(
        [
            f"Title: {group_id} requires remediation in {', '.join(projects) or 'the product'}",
            "",
            "Issue",
            f"Automated code analysis found that {group_id} may affect "
            f"{', '.join(components) or 'the assessed components'}.",
            "",
            "Analysis",
            f"- Component verdicts: {verdicts}",
            f"- Analysis runs: {run_ids}",
            f"- Severity: {_text(group.get('severity')) or 'Not reported'}",
            "",
            "Remediation",
            "- Update the affected dependency to a fixed version or safe range.",
            "- Validate the reachable code path and document any compensating control.",
            "",
            "Validation",
            f"- Rerun dependency and code analysis and confirm {group_id} "
            "no longer affects the product.",
        ]
    )


def _build_group_item(
    group: dict[str, Any],
    records: list[dict[str, Any]],
    applied_keys: set[tuple[str, str]],
) -> dict[str, Any] | None:
    assessment_entries: list[dict[str, Any]] = []
    for record in records:
        assessment = _record_assessment(record)
        if assessment is None:
            continue
        verdict = normalize_verdict(assessment)
        assessment_entries.append(
            {
                "record": record,
                "assessment": assessment,
                "verdict_bucket": verdict,
            }
        )
    if not assessment_entries:
        return None

    worst = max(
        assessment_entries,
        key=lambda entry: VERDICT_PRIORITY[entry["verdict_bucket"]],
    )
    overall_verdict = worst["verdict_bucket"]
    target_state = verdict_state(overall_verdict)
    justification = (
        "CODE_NOT_PRESENT"
        if overall_verdict == "NOT_AFFECTED"
        and all(
            _lower(entry["assessment"].get("exposure")) == "none"
            for entry in assessment_entries
        )
        else "CODE_NOT_REACHABLE"
        if overall_verdict == "NOT_AFFECTED"
        else "NOT_SET"
    )
    run_ids = sorted(
        {
            _record_run_id(entry["record"])
            for entry in assessment_entries
            if _record_run_id(entry["record"])
        }
    )
    target_details = _assessment_details(
        assessment_entries,
        verdict=overall_verdict,
        state=target_state,
        justification=justification,
    )

    eligible_instances: list[dict[str, Any]] = []
    already_applied_findings = 0
    preexisting_findings = 0
    missing_identity_findings = 0
    for instance in _instances(group):
        finding_key = _application_finding_key(instance)
        if not finding_key:
            missing_identity_findings += 1
            continue
        details = _text(
            instance.get("analysis_details") or instance.get("analysisDetails")
        )
        recorded_run_ids = {
            _text(value)
            for match in re.findall(r"\[Analysis Runs?: ([^\]]+)\]", details)
            for value in match.split(",")
            if _text(value)
        }
        if run_ids and all(
            (run_id, finding_key) in applied_keys or run_id in recorded_run_ids
            for run_id in run_ids
        ):
            already_applied_findings += 1
            continue
        state = _text(
            instance.get("analysis_state")
            or instance.get("analysisState")
            or "NOT_SET"
        ).upper()
        if state != "NOT_SET" or details:
            preexisting_findings += 1
        eligible_instances.append(
            {
                **instance,
                "_application_finding_key": finding_key,
            }
        )
    ticket_text = _ticket_text(group, assessment_entries)
    return {
        "group_id": _text(group.get("id")),
        "title": group.get("title"),
        "severity": group.get("severity"),
        "verdict_bucket": overall_verdict,
        "target_state": target_state,
        "target_justification": justification,
        "finding_count": len(_instances(group)),
        "eligible_finding_count": len(eligible_instances),
        "already_applied_finding_count": already_applied_findings,
        "preexisting_finding_count": preexisting_findings,
        "missing_identity_finding_count": missing_identity_findings,
        "run_ids": run_ids,
        "assessment_fingerprint": hashlib.sha256(
            target_details.encode("utf-8")
        ).hexdigest(),
        "ticket_text": ticket_text,
        "ticket_required": bool(ticket_text),
        "target_details": target_details,
        "instances": eligible_instances,
    }


def build_automatic_assessment_preview(context: BulkWorkflowContext) -> dict[str, Any]:
    diagnostics: dict[str, int] = {}
    records = _latest_assessment_records(context, diagnostics)
    record_index = _records_by_vulnerability(records)
    group_records = [
        (group, _matched_records_for_group(group, record_index))
        for group in context.groups
    ]
    applied_keys = _application_keys(context, _unique_records(group_records))
    full_items: list[dict[str, Any]] = []
    for group, matched_records in group_records:
        item = _build_group_item(group, matched_records, applied_keys)
        if item is not None:
            full_items.append(item)
    eligible_items = [
        item for item in full_items if item["eligible_finding_count"] > 0
    ]
    items = [
        {
            key: value
            for key, value in item.items()
            if key not in {"instances", "target_details"}
        }
        for item in sorted(eligible_items, key=lambda item: item["group_id"])
    ]
    return {
        "items": items,
        "summary": {
            "groups": len(items),
            "findings": sum(item["eligible_finding_count"] for item in items),
            "not_affected_groups": sum(
                item["verdict_bucket"] == "NOT_AFFECTED" for item in items
            ),
            "affected_groups": sum(
                item["verdict_bucket"] == "AFFECTED" for item in items
            ),
            "probably_affected_groups": sum(
                item["verdict_bucket"] == "PROBABLY_AFFECTED" for item in items
            ),
            "inconclusive_groups": sum(
                item["verdict_bucket"] == "INCONCLUSIVE" for item in items
            ),
            **diagnostics,
            "matched_analysis_results": len(_unique_records(group_records)),
            "matched_assessment_groups": len(full_items),
            "already_applied_findings": sum(
                item["already_applied_finding_count"] for item in full_items
            ),
            "missing_identity_findings": sum(
                item["missing_identity_finding_count"] for item in full_items
            ),
        },
    }


def build_automatic_assessment_payloads(
    context: BulkWorkflowContext,
    group_ids: list[str],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]]:
    group_records = _selected_group_records(context, group_ids)
    applied_keys = _application_keys(context, _unique_records(group_records))
    payloads: list[tuple[dict[str, Any], dict[str, Any]]] = []
    skipped = {
        "already_applied": 0,
        "missing_identity": 0,
        "replaced_existing": 0,
    }
    for group, matched_records in group_records:
        item = _build_group_item(group, matched_records, applied_keys)
        if item is None:
            continue
        skipped["already_applied"] += item["already_applied_finding_count"]
        skipped["missing_identity"] += item["missing_identity_finding_count"]
        skipped["replaced_existing"] += item["preexisting_finding_count"]
        for raw_instance in item["instances"]:
            instance = dict(raw_instance)
            identity_keys = (
                "project_uuid",
                "component_uuid",
                "vulnerability_uuid",
            )
            if not all(instance.get(key) for key in identity_keys):
                skipped["missing_identity"] += 1
                continue
            instance["finding_uuid"] = instance.pop(
                "_application_finding_key",
                _application_finding_key(instance),
            )
            instance["analysis_run_ids"] = list(item["run_ids"])
            instance["bulk_workflow_group_id"] = item["group_id"]
            payloads.append(
                (
                    instance,
                    {
                        "project_uuid": instance["project_uuid"],
                        "component_uuid": instance["component_uuid"],
                        "vulnerability_uuid": instance["vulnerability_uuid"],
                        "state": item["target_state"],
                        "details": item["target_details"],
                        "justification": item["target_justification"],
                        "suppressed": False,
                    },
                )
            )
    return payloads, skipped


def build_automatic_assessment_document(context: BulkWorkflowContext, group_ids: list[str]) -> str:
    group_records = _selected_group_records(context, group_ids)
    applied_keys = _application_keys(context, _unique_records(group_records))
    items = [
        item
        for group, records in group_records
        if (item := _build_group_item(group, records, applied_keys)) is not None
        and item.get("ticket_text")
    ]
    lines = ["# Automatic Assessment Ticket Drafts", ""]
    if not items:
        lines.append("No selected automatic assessments require a remediation ticket.")
        return "\n".join(lines) + "\n"
    for item in items:
        lines.extend(
            [
                f"## {item['group_id']}",
                "",
                item["ticket_text"],
                "",
                f"DTVP analysis run IDs: {', '.join(item['run_ids'])}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def create_automatic_assessment_workflow() -> BulkWorkflowPlugin:
    return BulkWorkflowPlugin(
        id="automatic-assessments",
        label="Apply Automatic Assessments",
        description=(
            "Apply each vulnerability's overall completed code-analysis verdict "
            "when it has not been applied yet."
        ),
        preview_builder=build_automatic_assessment_preview,
        payload_builder=build_automatic_assessment_payloads,
        document_builder=build_automatic_assessment_document,
        selection_predicate=lambda item: int(item.get("eligible_finding_count") or 0) > 0,
        version=7,
    )
