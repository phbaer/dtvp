"""Shared native Agentyzer availability and report normalization; no SQL execution."""

import re


def enabled(settings):
    return (settings.playground and not settings.agentyzer_enabled) or (
        settings.agentyzer_enabled and bool(settings.agentyzer_url)
    )


def mode(settings):
    return "synthetic" if settings.playground and not settings.agentyzer_enabled else "external"


def normalize(report, target, *, synthetic=False):
    assessment = report.get("assessment")
    if not isinstance(assessment, dict):
        raise ValueError("Agentyzer returned no assessment")
    version = assessment.get("version_analysis") or {}
    comparison = version.get("comparison_inputs") or {} if isinstance(version, dict) else {}
    target_verified = (
        isinstance(comparison, dict)
        and comparison.get("component_name") == target["package_name"]
        and version.get("detected_version") == target["version"]
        and bool(target["version"])
    )
    expected = target.get("source_binding", {})
    source = report.get("source_input")
    source = source if isinstance(source, dict) else {}
    commit = expected.get("source_commit")
    source_verified = (
        expected.get("status") == "known"
        and isinstance(commit, str)
        and re.fullmatch(r"[0-9a-f]{40}", commit) is not None
        and source.get("binding") == "verified_git_commit"
        and source.get("requested_commit") == commit
        and source.get("resolved_commit") == commit
    )
    source_reason = (
        "Synthetic playground result; source identity is unverified"
        if synthetic
        else ""
        if source_verified
        else expected.get("reason") or "Agentyzer did not verify the requested source commit"
    )
    application = (
        assessment.get("application_eligible") is True
        and target_verified
        and (source_verified or synthetic)
    )
    rescoring = assessment.get("rescoring_eligible") is True and application
    affected = assessment.get("affected")
    coverage = assessment.get("code_coverage") or {}
    exclusion = isinstance(coverage, dict) and coverage.get("permits_exclusion") is True
    proposal = (
        "affected"
        if application and affected is True and assessment.get("analysis") == "EXPLOITABLE"
        else "not_affected"
        if application
        and affected is False
        and exclusion
        and assessment.get("analysis") in {"NOT_AFFECTED", "FALSE_POSITIVE"}
        else None
    )
    return {
        "kind": "code-analysis",
        "application_eligible": application,
        "target_verified": target_verified,
        "source_verified": source_verified and not synthetic,
        "source_binding": {
            "status": "synthetic_unverified"
            if synthetic
            else "verified"
            if source_verified
            else "unverified",
            "expected_commit": commit,
            "requested_commit": str(source.get("requested_commit") or "")[:100],
            "resolved_commit": str(source.get("resolved_commit") or "")[:100],
            "reason": source_reason,
        },
        "ineligibility_reasons": ([source_reason] if not synthetic and not source_verified else [])
        + (["Package/version evidence does not match the finding"] if not target_verified else [])
        + (
            ["Provider did not mark this result application-eligible"]
            if assessment.get("application_eligible") is not True
            else []
        ),
        "rescoring_eligible": rescoring,
        "proposal_state": proposal,
        "summary": str(assessment.get("summary") or "No summary supplied")[:2000],
        "rationale": str(assessment.get("reasoning") or assessment.get("summary") or "")[:6000],
        "verdict": str(assessment.get("verdict") or "Unknown")[:100],
        "confidence": str(assessment.get("confidence") or "Unknown")[:100],
        "code_coverage": {"permits_exclusion": exclusion},
    }
