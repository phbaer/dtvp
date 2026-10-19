"""Detail-only evidence contributions; observed claims never imply adoption or independence."""

from dtvp.knowledge.metadata import component_at
from dtvp.storage import canonical, digest

FORMAT = "dtvp.evidence-contributions/1"
LIMIT = 100


def text(value, limit=500):
    return str(value or "")[:limit]


def entry(
    identity,
    *,
    kind,
    provider,
    label=None,
    status="unknown",
    current=None,
    summary="",
    ratings=(),
    proposal=None,
    claims=None,
    provenance=None,
    diagnostics=(),
):
    return {
        "id": identity,
        "kind": kind,
        "provider": text(provider, 200) or "Unknown",
        "label": text(label or provider, 300) or "Unknown source",
        "status": status,
        "current": current,
        "summary": text(summary),
        "ratings": list(ratings),
        "proposal": proposal,
        "claims": claims or {},
        "adoption": {
            "status": "not_recorded",
            "assessment_revisions": [],
            "published_score": False,
        },
        "provenance": provenance or {},
        "diagnostics": list(diagnostics),
    }


def source_name(value):
    if isinstance(value, dict):
        return text(value.get("name") or value.get("url"), 300) or "Unknown"
    return text(value, 300) or "Unknown"


def source_summary(advisory):
    parts = (
        ["Description available"] if advisory.get("description") or advisory.get("title") else []
    )
    ratings = advisory.get("ratings", [])
    if ratings:
        parts.append(
            "Ratings: "
            + ", ".join(
                f"{rating.get('score', 'unknown')} {rating.get('method') or ''}{' (' + source_name(rating['source']) + ')' if rating.get('source') else ''}".strip()
                for rating in ratings[:4]
            )
        )
    if advisory.get("status"):
        parts.append("Status: " + text(advisory["status"], 80))
    if advisory.get("references"):
        parts.append(f"{len(advisory['references'])} references")
    return "; ".join(parts) or "Occurrence assertion; description, ratings and status are unknown."


def scoped_statement(
    statement, application, component, ref, identifier, document_sha, baseline_sha
):
    from dtvp.knowledge.vex import exact_purl

    if statement.get("vulnerability_id") != identifier:
        return False
    if ref in application.get("matched", []):
        return True
    if statement.get("known_identifier_only"):
        return True
    selected = exact_purl(component.get("purl"))
    if selected and any(
        exact_purl(value) == selected
        for value in [*statement.get("purls", []), *statement.get("product_ids", [])]
    ):
        return True
    for scope in statement.get("source_refs", []):
        if not isinstance(scope, dict):
            continue
        declared = exact_purl((scope.get("component") or {}).get("purl"))
        if selected and declared == selected:
            return True
        if (
            not declared
            and document_sha
            and document_sha == baseline_sha
            and scope.get("ref") == ref
        ):
            return True
    return False


def source_entries(sections, row, component):
    items = []
    baseline = sections["inventory"].get("baseline", {})
    observed_documents = set()
    for observation in row.get("sourcefacts", []):
        if (
            observation.get("ref") != row["context"]["component_ref"]
            or observation.get("identifier") != row["vulnerability_id"]
        ):
            continue
        advisory = observation.get("advisory", {})
        identity = observation.get("observation_id") or digest(canonical(observation))
        artifact = (
            observation.get("document_sha")
            or observation.get("artifact_sha")
            or baseline.get("artifact_sha")
        )
        if observation.get("document_sha"):
            observed_documents.add(observation["document_sha"])
        provider = source_name(observation.get("publisher") or advisory.get("source"))
        if provider == "Unknown":
            provider = source_name(observation.get("source"))
        kind = {
            "external-status": "vex",
            "external-advisory": "advisory",
            "external-match": "package_matching",
        }.get(observation.get("kind"), "inventory_source")
        items.append(
            entry(
                identity,
                kind=kind,
                provider=provider,
                label=f"{provider} · {source_name(observation.get('source'))}",
                status="current",
                current=True,
                summary=source_summary(advisory),
                ratings=advisory.get("ratings", []),
                claims={
                    "description": advisory.get("description") or advisory.get("title"),
                    "status": advisory.get("status"),
                    "applicability": advisory.get("normalized_status"),
                    "references": advisory.get("references", []),
                    "source": advisory.get("source"),
                    "source_scope": observation.get("source_scope"),
                    "provider_identity": "source_claim_not_authenticated",
                    "contributes": [
                        key
                        for key, available in (
                            ("description", bool(advisory.get("description"))),
                            ("ratings", bool(advisory.get("ratings"))),
                            ("status", bool(advisory.get("status"))),
                            ("references", bool(advisory.get("references"))),
                        )
                        if available
                    ],
                },
                provenance={
                    "observation_id": identity,
                    "record_key": identity,
                    "component_ref": observation.get("ref"),
                    "artifact_sha256": artifact,
                    "artifact_basis": "document"
                    if observation.get("document_sha")
                    else "observation"
                    if observation.get("artifact_sha")
                    else "selected_baseline",
                    "baseline_source_provenance": baseline.get("source_provenance"),
                    "source": observation.get("source"),
                    "source_origin": observation.get("dtvp_origin"),
                    "publisher": observation.get("publisher"),
                },
                diagnostics=[],
            )
        )
    for key, record in sorted(sections["vulnerabilities"].items()):
        if not key.startswith("evidence-document:"):
            continue
        document = record.get("document", {})
        active = record.get("active", True)
        sha = record.get("artifact_sha")
        provenance = {
            "record_key": key,
            "artifact_sha256": sha,
            "source": record.get("source"),
            "source_revision": record.get("source_revision"),
            "imported_at": record.get("imported_at"),
            "additional_artifacts": record.get("additional_artifacts", []),
        }
        provider = source_name(
            document.get("publisher") or record.get("source") or "Imported document"
        )
        raw = document.get("raw", {})
        for index, lookup in enumerate(raw.get("refresh", {}).get("lookups", [])):
            if lookup.get("identifier") != row["vulnerability_id"]:
                continue
            if lookup.get("status") == "found" and sha in observed_documents:
                continue
            status = text(lookup.get("status")) or "unknown"
            items.append(
                entry(
                    f"{key}:lookup:{index}",
                    kind="advisory_lookup",
                    provider=provider,
                    status=status if active else "inactive",
                    current=active,
                    summary=f"Exact identifier retrieval: {status}. This does not establish affectedness or absence of vulnerabilities.",
                    claims={"retrieval_status": status, "identifier": row["vulnerability_id"]},
                    provenance={
                        **provenance,
                        "response_sha256": lookup.get("response_sha256"),
                        "capture_sha256": raw.get("refresh", {}).get("capture_sha256"),
                    },
                    diagnostics=[]
                    if active
                    else ["Superseded or withdrawn document retained historically."],
                )
            )
        matching = document.get("matching_coverage", {})
        if (
            component.get("purl")
            and matching.get("purl") == component["purl"]
            and matching.get("status") == "no_matches_reported"
        ):
            items.append(
                entry(
                    key + ":coverage",
                    kind="package_matching",
                    provider=provider,
                    status="no_matches_reported" if active else "inactive",
                    current=active,
                    summary="Exact package query returned no matches; this is a provider coverage claim, not a not-affected assessment.",
                    claims=matching,
                    provenance=provenance,
                )
            )
        applications = {
            value["statement_index"]: value
            for value in record.get("application", {}).get("statements", [])
        }
        for index, statement in enumerate(document.get("statements", [])):
            application = applications.get(index, {})
            if not scoped_statement(
                statement,
                application,
                component,
                row["context"]["component_ref"],
                row["vulnerability_id"],
                sha,
                baseline.get("artifact_sha"),
            ):
                continue
            if (
                active
                and sha in observed_documents
                and row["context"]["component_ref"] in application.get("matched", [])
            ):
                continue
            reasons = application.get("unresolved", []) or statement.get("unresolved_reasons", [])
            items.append(
                entry(
                    f"{key}:statement:{index}",
                    kind="document_statement",
                    provider=provider,
                    status="unmatched" if active else "inactive",
                    current=active,
                    summary=statement.get("rationale")
                    or f"{document.get('format', 'Imported')} statement: {statement.get('status', 'unknown')}; no active assertion for this occurrence.",
                    claims={
                        "status": statement.get("status"),
                        "applicability": statement.get("normalized_status"),
                        "format": document.get("format"),
                    },
                    provenance={**provenance, "statement_index": index},
                    diagnostics=reasons
                    or ["Historical or unbound statement; not a current DTVP assessment."],
                )
            )
    return items


def analysis_entries(row):
    items = []
    code_ids = {item["id"] for item in row.get("code_analysis", [])}
    scoring = {item["id"]: item for item in row.get("scoring_proposals", [])}
    for proposal in row.get("scoring_proposals", []):
        if proposal["id"] in code_ids:
            continue
        if proposal.get("target") and any(
            proposal["target"].get(key) != row[key] for key in ("context_id", "vulnerability_id")
        ):
            continue
        current = proposal.get("current", False)
        value = proposal.get("proposal")
        summary = (
            f"Proposed contextual score {value['score']} from source Base {value['base_score']}."
            if value
            else "Provider withheld a usable contextual scoring proposal."
        )
        items.append(
            entry(
                proposal["id"],
                kind="scoring_analysis",
                provider=proposal.get("provider"),
                label=proposal.get("source_label"),
                status="stale"
                if not current
                else "eligible"
                if proposal.get("eligible")
                else "withheld",
                current=current,
                summary=summary,
                proposal=value,
                claims={
                    "proposal_id": proposal["id"],
                    "eligible": bool(proposal.get("eligible")),
                    "verification": proposal.get("verification"),
                    "provider_authenticity": proposal.get("provider_authenticity"),
                },
                provenance={
                    "record_key": "proposal:" + proposal["id"],
                    "report_sha256": proposal.get("report_sha256"),
                    "receipt_sha256": proposal.get("receipt_sha256"),
                    "source_receipt": proposal.get("source_receipt"),
                    "source_assessment_id": proposal.get("source_assessment_id"),
                    "source_finding_id": proposal.get("source_finding_id"),
                },
                diagnostics=proposal.get("ineligibility_reasons", []),
            )
        )
    for analysis in row.get("code_analysis", []):
        if analysis.get("target") and any(
            analysis["target"].get(key) != row[key] for key in ("context_id", "vulnerability_id")
        ):
            continue
        current = analysis.get("current", False)
        summary = f"Verdict: {analysis.get('verdict') or 'unknown'}"
        if analysis.get("proposal_state"):
            summary += f"; applicability proposal: {analysis['proposal_state']}"
        if analysis.get("proposal"):
            summary += f"; proposed contextual score: {analysis['proposal']['score']}"
        items.append(
            entry(
                analysis["id"],
                kind="code_analysis",
                provider=analysis.get("provider"),
                label=analysis.get("source_label"),
                status="stale"
                if not current
                else "eligible"
                if analysis.get("application_eligible")
                else "withheld",
                current=current,
                summary=summary,
                proposal=analysis.get("proposal"),
                claims={
                    "proposal_id": analysis["id"] if analysis["id"] in scoring else None,
                    "eligible": bool(scoring.get(analysis["id"], {}).get("eligible")),
                    "verdict": analysis.get("verdict"),
                    "proposed_applicability": analysis.get("proposal_state"),
                    "rationale": analysis.get("rationale"),
                    "summary": analysis.get("summary"),
                    "confidence": analysis.get("confidence"),
                    "provider_authenticity": analysis.get("provider_authenticity"),
                    "job_report_association": analysis.get("job_report_association"),
                    "repository_authorization": analysis.get("repository_authorization"),
                    "provider_claim": analysis.get("provider_claim"),
                    "application_eligible": bool(analysis.get("application_eligible")),
                    "rescoring_eligible": bool(analysis.get("rescoring_eligible")),
                },
                provenance={
                    "record_key": "code-analysis:" + analysis["id"],
                    "report_sha256": analysis.get("report_sha256"),
                    "receipt_sha256": analysis.get("receipt_sha256"),
                    "source_receipt": analysis.get("source_receipt"),
                    "source_proof": analysis.get("source_proof"),
                },
                diagnostics=[
                    *analysis.get("ineligibility_reasons", []),
                    *analysis.get("scoring_blockers", []),
                ],
            )
        )
    for legacy in row.get("legacy_evidence", []):
        items.append(
            entry(
                legacy["id"],
                kind="imported_legacy_analysis",
                provider=legacy.get("source") or "Imported DT analysis",
                status="historical_claim",
                current=None,
                summary=f"Imported applicability: {legacy.get('proposed_applicability') or legacy.get('status', 'unknown')}; {len(legacy.get('records', []))} historical records; {len(legacy.get('scoring_proposals', []))} scoring claims.",
                claims={
                    "applicability": legacy.get("proposed_applicability"),
                    "conflicting": legacy.get("conflicting"),
                    "legacy_format": legacy.get("legacy_format"),
                    "authenticated_identity": False,
                    "rationale": legacy.get("shared_text") or legacy.get("raw_text"),
                    "scoring_proposals": legacy.get("scoring_proposals", []),
                },
                provenance={
                    "observation_id": legacy.get("original_source_ref", {}).get("observation_id"),
                    "record_id": legacy["id"],
                    "original_source_ref": legacy.get("original_source_ref"),
                },
                diagnostics=[
                    *legacy.get("errors", []),
                    "Imported author/reviewer labels do not establish DTVP approval.",
                ],
            )
        )
    return items


def mark_references(items, row):
    records = [
        row.get("coverage", {}).get("assessment"),
        row.get("coverage", {}).get("approved_assessment"),
    ]
    for item in items:
        known = {
            "proposal_id": item["id"],
            "observation_id": item["provenance"].get("observation_id"),
            "artifact_sha256": item["provenance"].get("artifact_sha256"),
            "report_sha256": item["provenance"].get("report_sha256"),
        }
        revisions = set()
        for record in records:
            if not record:
                continue
            for evidence in record.get("payload", {}).get("evidence", []):
                if isinstance(evidence, dict) and any(
                    value and evidence.get(key) == value for key, value in known.items()
                ):
                    revisions.add(record["revision"])
        if revisions:
            item["adoption"].update(status="referenced", assessment_revisions=sorted(revisions))
            item["diagnostics"].append(
                "Exact assessment evidence citation recorded; citation alone does not prove adoption or approval."
            )


def cpe_entries(journal, project_id, component, state):
    from dtvp.knowledge.cpe import current_discovery_policy, propose_for_component
    from dtvp.knowledge.cpe_ranking import rank_candidates

    result = {
        "declared": [],
        "curated": [],
        "accepted": [],
        "candidates": [],
        "diagnostics": [
            "No native CPE acceptance record exists; configured mappings and ranked candidates are not approved identity."
        ],
    }
    ref = component.get("bom-ref")
    if component.get("cpe"):
        result["declared"].append(
            entry(
                "declared:" + digest(canonical([ref, component["cpe"]])),
                kind="declared_cpe",
                provider="Imported component",
                status="declared",
                current=True,
                summary=component["cpe"],
                claims={"cpe": component["cpe"], "applicability": "not_assessed"},
                provenance={"component_ref": ref, "inventory_state": state},
            )
        )
    policy, config = current_discovery_policy(journal, project_id)
    if not policy:
        result["diagnostics"].append(
            "No configured CPE discovery policy; no dictionary search was run."
        )
        return result
    provenance = {
        "policy_state": policy,
        "inventory_state": state,
        "policy_relation": "current_project_policy_not_inventory_pin",
    }
    try:
        proposal = propose_for_component(
            component, config.get("catalog", []), config.get("rules", {})
        )
        for index, rule in enumerate(proposal["reviewed_rules"][:20]):
            result["curated"].append(
                entry(
                    f"{policy}:rule:{index}",
                    kind="configured_cpe_mapping",
                    provider=rule.get("source"),
                    status="curated_mapping",
                    current=None,
                    summary=rule.get("cpe") or f"Alias to {rule.get('target_purl')}",
                    claims=rule,
                    provenance=provenance,
                )
            )
        if len(proposal["reviewed_rules"]) > 20:
            result["diagnostics"].append(
                "Configured mapping chain limited to 20 entries; use the dedicated CPE tool for all rules."
            )
        candidates = proposal["candidates"]
        if config.get("retained_dictionary"):
            if len(config["retained_dictionary"]) > 2000:
                result["diagnostics"].append(
                    "Retained dictionary exceeds compact detail ranking budget; use the dedicated CPE tool."
                )
            else:
                ranking = rank_candidates(
                    component,
                    config["retained_dictionary"],
                    config.get("catalog", []),
                    config.get("rules", {}),
                    limit=20,
                )
                candidates = [*candidates, *ranking["candidates"]]
                result["diagnostics"].extend([f"Dictionary ranking: {ranking['ambiguity']}"])
                if ranking["counts"]["rejected"]:
                    result["diagnostics"].append(
                        f"Dictionary records rejected for this component: {ranking['counts']['rejected']}."
                    )
        for index, candidate in enumerate(candidates[:20]):
            result["candidates"].append(
                entry(
                    f"{policy}:candidate:{index}",
                    kind="cpe_candidate",
                    provider=source_name(
                        candidate.get("record", {}).get("source")
                        or candidate.get("provenance", {}).get("source")
                        or "Configured CPE discovery"
                    ),
                    status="candidate",
                    current=None,
                    summary=candidate["cpe"],
                    claims=candidate,
                    provenance={**provenance, "rank": index + 1},
                    diagnostics=[
                        "Candidate identity and ranking do not establish affectedness or adoption."
                    ],
                )
            )
        if len(candidates) > 20:
            result["diagnostics"].append(
                "Candidate list limited to 20; complete CPE tools remain available."
            )
        result["diagnostics"].extend(
            text(item.get("reason")) for item in proposal.get("rejected_candidates", [])
        )
    except ValueError as error:
        result["diagnostics"].append(text(error))
    return result


def contributions(journal, state, row):
    from dtvp.knowledge.workspace import load_sections

    revision = journal.state(state)
    sections = load_sections(journal, state)
    ref = row["context"]["component_ref"]
    component = component_at(sections, ref) or row.get("component", {})
    sources = source_entries(sections, row, component)
    analyses = analysis_entries(row)
    mark_references([*sources, *analyses], row)
    limitations = [
        "Current source/analysis status refers to the selected inventory state; CPE policy evaluation is separately labeled.",
        "Active facts and provider claims are not independently authenticated or necessarily independent sources.",
        "Eligible proposals are not adopted decisions; score/vector equality does not prove analysis use.",
        "Exact citations describe recorded references, not a new assessment, approval or published-score linkage.",
        "Raw observations, reports and existing evidence tools remain available for detailed inspection.",
    ]
    if len(sources) > LIMIT or len(analyses) > LIMIT:
        limitations.append(
            "Compact groups are limited to 100 entries; raw detail remains available."
        )
    return {
        "format": FORMAT,
        "scope": {
            "state": state,
            "version": revision.version,
            "context_id": row["context_id"],
            "component_ref": ref,
            "vulnerability_id": row["vulnerability_id"],
        },
        "vulnerability_sources": sources[:LIMIT],
        "vulnerability_analyses": analyses[:LIMIT],
        "cpe": cpe_entries(journal, revision.project_id, component, state),
        "limitations": limitations,
    }
