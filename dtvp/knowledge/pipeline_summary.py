"""Pinned pipeline observations; downstream policy must supply any release decision."""

from collections import Counter
from urllib.parse import quote

from dtvp.api_contract import API_PREFIX
from dtvp.knowledge.comparison import product_state
from dtvp.knowledge.documents import list_documents
from dtvp.knowledge.filters import metadata_status, scoring_status
from dtvp.knowledge.input_quality import input_quality
from dtvp.knowledge.license_reviews import list_license_reviews
from dtvp.knowledge.licenses import license_worklist
from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.storage import canonical, digest

FORMAT = "dtvp.pipeline-evidence-summary/1"
LIMITATIONS = {
    "no_release_verdict": "Counts are observations, not a release gate, compliance certification or legal clearance.",
    "producer_input_boundary": "Composition and discovery coverage are producer declarations, not verified completeness or correctness.",
    "pinned_history_only": "Only this exact state is summarized; newer imports, policies, advisories and other versions are not consulted.",
    "zero_is_not_clearance": "No findings, licenses or documents may mean missing evidence; zero never establishes clearance.",
    "context_counts": "Findings and team reviews are contextual; one vulnerability can require multiple assessments.",
    "retained_is_not_current": "Absent, stale and out-of-scope records remain historical evidence, not current approvals.",
    "document_boundary": "Document review and input currency do not establish renderer correctness or regulatory compliance.",
}


def _counts(values):
    return dict(sorted(Counter(values).items()))


def pipeline_summary(journal, state):
    revision = journal.verify_state(state)
    product_state(journal, state, revision.project_id)
    sections = load_sections(journal, state)
    workspace = load_workspace(journal, state, paginate=False)
    findings, statistics = workspace["items"], workspace["statistics"]
    quality = input_quality(journal, state, limit=1)
    licenses = license_worklist(journal, state, paginate=False)
    dispositions = list_license_reviews(journal, sections, revision.version, paginate=False)
    documents = list_documents(journal, state, paginate=False)
    coverage = [row["coverage"] for row in findings]
    license_rows = [row["license_review"] for row in licenses["items"]]
    document_rows = documents["items"]
    assembly = sections["inventory"].get("assembly")
    source_coverage = {}
    for dimension in ("package_coverage", "dependency_coverage", "license_coverage"):
        source_coverage[dimension] = _counts(
            source["collection"].get(dimension, "unknown") for source in quality["sources"]
        )
    path = f"{API_PREFIX}/projects/{quote(revision.project_id, safe='')}/states/{state}"
    content = {
        "format": FORMAT,
        "state": state,
        "project_id": revision.project_id,
        "version": revision.version,
        "section_hashes": revision.sections,
        "inventory": {
            "baseline_status": quality["baseline_status"],
            "source_count": len(quality["sources"]),
            "producer_declared_coverage": source_coverage,
            "coverage_verification": "not_verified",
            "assembly": {
                "readiness": assembly.get("readiness", "unknown"),
                "coherence_status": assembly.get("coherence", {}).get("status", "unverified"),
                "selected_parts": sum(
                    part.get("availability") == "selected" for part in assembly.get("parts", [])
                ),
                "missing_required_parts": sum(
                    bool(part.get("required")) and not part.get("state")
                    for part in assembly.get("parts", [])
                ),
            }
            if assembly is not None
            else None,
            "quality_report_digest": quality["report_digest"],
            "quality_statistics": {
                key: value for key, value in quality["statistics"].items() if key != "by_source"
            },
        },
        "vulnerabilities": {
            "totals": statistics["totals"],
            "by_review_status": statistics["by_status"],
            "by_team": statistics["by_team"],
            "team_counts_overlap": statistics["team_counts_overlap"],
            "source_severity": statistics["severity"],
            "scoring": _counts(scoring_status(row) for row in findings),
            "annotations": _counts(metadata_status(row) for row in findings),
            "approved_with_newer_pending_revision": sum(
                bool(
                    value.get("approved")
                    and value.get("approved_assessment")
                    and value.get("assessment")
                )
                and value["approved_assessment"]["revision"] != value["assessment"]["revision"]
                for value in coverage
            ),
            "ownership": {
                key: statistics[key]
                for key in ("unassigned", "ownership_conflicts", "topology_unknown")
            },
            "source_observations": len(sections["vulnerabilities"]),
            "uncontextualized_source_finding_keys": statistics["uncontextualized_source_findings"],
        },
        "licenses": {
            **licenses["statistics"],
            "current_approved_components": sum(value["approved"] for value in license_rows),
            "approved_with_newer_pending_revision": sum(value["pending"] for value in license_rows),
            "retained_dispositions": dispositions["total"],
            "retained_by_status": dispositions["by_status"],
        },
        "documents": {
            "recorded": documents["total"],
            "by_status": documents["by_status"],
            "latest_source_current": sum(value["source_current"] for value in document_rows),
            "current_approved": sum(value["approved_source_current"] for value in document_rows),
            "historical_approved": sum(
                bool(value["approved_document"]) and not value["approved_source_current"]
                for value in document_rows
            ),
            "approved_with_newer_pending_revision": sum(
                value["pending"] for value in document_rows
            ),
            "out_of_scope_review_history": sum(
                bool(value["historical_review"]) for value in document_rows
            ),
        },
        "retained": {
            key: statistics[key]
            for key in (
                "retained_assessments",
                "retained_absent_assessments",
                "retained_unknown_scope_assessments",
            )
        },
        "reports": {
            "input_quality": path + "/input-quality",
            "consumer_bundle": path + "/bundle",
            "licenses": path + "/license-worklist",
            "documents": path + "/documents",
        },
        "limitations": [
            {"code": code, "description": description} for code, description in LIMITATIONS.items()
        ],
    }
    return {**content, "summary_digest": digest(canonical(content))}
