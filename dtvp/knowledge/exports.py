"""Pinned native consumer evidence; digests establish integrity, not approval."""

from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.rescoring import base_fact
from dtvp.storage import canonical, digest

BUNDLE_FORMAT = "dtvp.knowledge-bundle/1"
EXPORT_FORMAT = "dtvp.knowledge-export/1"
WORKLIST_FORMAT = "dtvp.knowledge-vscorer-worklist/1"


def _workspace(journal, state):
    """One pinned complete read; pagination remains an API presentation concern."""
    return load_workspace(journal, state, paginate=False)


def _retained_absent(sections, version, findings):
    active = {(row["context_id"], row["vulnerability_id"]) for row in findings}
    absent = []
    for key, record in sorted(sections["assessments"].items()):
        targets = [
            target
            for target in record.get("payload", {}).get("targets", [])
            if target.get("version") == version
            and (target.get("context_id"), target.get("vulnerability_id")) not in active
        ]
        if targets:
            absent.append({"record_id": key, "targets": targets, "assessment": record})
    return absent


def _inventory(records):
    known = {"baseline", "dependencies", "relationships", "root", "assembly"}
    result = {
        "baseline": records.get("baseline", {}),
        "components": [
            value for key, value in sorted(records.items()) if key.startswith("component:")
        ],
        "root": records.get("root", {}),
        "part_roots": {
            key: value for key, value in sorted(records.items()) if key.startswith("part-root:")
        },
        "dependencies": records.get("dependencies", {"edges": []}),
        "relationships": records.get("relationships", {"items": []}),
        "other_records": {
            key: value
            for key, value in sorted(records.items())
            if key not in known and not key.startswith(("component:", "part-root:"))
        },
    }
    if "assembly" in records:
        result["assembly"] = records["assembly"]
    return result


def build_bundle(journal, state):
    """Export complete evidence from exactly one hash-verified state.

    No current policy, external provider, authorization-dependent filtering or
    mutable reference resolution is consulted. Callers authorize the full state.
    """
    revision = journal.verify_state(state)
    sections = load_sections(journal, state)
    workspace = _workspace(journal, state)
    findings = workspace["items"]
    contextualized = {
        observation["observation_id"] for row in findings for observation in row["sourcefacts"]
    }
    observations = [
        {"observation_id": key, **value}
        for key, value in sorted(sections["vulnerabilities"].items())
    ]
    bundle = {
        "format": BUNDLE_FORMAT,
        "state": state,
        "project_id": revision.project_id,
        "version": revision.version,
        "inventory": _inventory(sections["inventory"]),
        "ownership": sections["ownership"],
        "findings": findings,
        "source_observations": observations,
        "uncontextualized_source_findings": [
            observation
            for observation in observations
            if observation["observation_id"] not in contextualized
        ],
        "retained_assessments": sections["assessments"],
        "retained_absent_assessments": _retained_absent(sections, revision.version, findings),
        "retained_reviews": sections["reviews"],
        "retained_scoring": sections["scoring"],
        "history": sections["history"],
        "statistics": workspace["statistics"],
        "limitations": [
            "Input correctness and declared completeness remain the producer's responsibility.",
            "Missing topology, ownership and assessment coverage remain unknown or unresolved.",
            "Imported claims and external proposals are distinct from current human approvals.",
            "This native v3 contract is not the v2 dtvp.snapshot/1 consumer contract.",
            "This export does not establish license clearance, architecture approval or regulatory compliance.",
        ],
    }

    # Optional enrichment preserves existing bytes when no dispositions exist.
    # Full server-derived status prevents consumers from mistaking a pending
    # record or inherited review for current independently approved clearance.
    if any(key.startswith("license-disposition:") for key in sections["history"]):
        from dtvp.knowledge.license_reviews import list_license_reviews

        bundle["license_dispositions"] = {
            "format": "dtvp.license-disposition-register/1",
            **list_license_reviews(journal, sections, revision.version, paginate=False),
        }
    if any(key.startswith("metadata:") for key in sections["history"]):
        from dtvp.knowledge.metadata import list_metadata

        # Consumers present server-derived applicability instead of treating raw
        # historical annotations as current facts. No metadata keeps old bytes.
        bundle["component_metadata"] = {
            "format": "dtvp.component-metadata-register/1",
            **list_metadata(journal, sections, revision.version, paginate=False),
        }
    if "pipeline_configuration" in sections["inventory"]:
        from dtvp.knowledge.pipeline_config import resolve_context, retained_config

        configuration = sections["inventory"]["pipeline_configuration"]["state"]
        bundle["pipeline_context"] = {
            **resolve_context(
                journal,
                project_id=revision.project_id,
                state=state,
                configuration=configuration,
                paginate=False,
            ),
            "configuration": retained_config(journal, revision.project_id, configuration),
        }
    return bundle


def export_bytes(journal, state):
    """Return canonical bundle bytes and a deterministic content-integrity manifest."""
    bundle = build_bundle(journal, state)
    revision = journal.state(state)
    raw = canonical(bundle)
    inventory = bundle["inventory"]
    sources = {}
    baseline = inventory["baseline"]
    if baseline.get("artifact_sha"):
        sha = baseline["artifact_sha"]
        sources[sha] = {"sha256": sha, "representation": baseline.get("representation", "unknown")}
    selected_sources = []
    for part in inventory.get("assembly", {}).get("parts", []):
        source_state = part.get("state")
        part_baseline = part.get("baseline", {})
        if source_state:
            source = journal.verify_state(source_state)
            if source.project_id != revision.project_id or source.version != revision.version:
                raise ValueError("Constituent source state belongs to another product version")
            selected_sources.append({"part_id": part["part_id"], "state": source_state})
        if part_baseline.get("artifact_sha"):
            sha = part_baseline["artifact_sha"]
            sources.setdefault(sha, {"sha256": sha})
            sources[sha].setdefault("parts", []).append(
                {
                    "part_id": part["part_id"],
                    "state": source_state,
                    "representation": part_baseline.get("representation", "unknown"),
                }
            )
    for sha in revision.artifacts:
        sources.setdefault(sha, {"sha256": sha, "representation": "unknown"})
    # Check named source objects even if an older/custom state omitted direct refs.
    for sha in sources:
        journal.objects.read(sha)
    manifest = {
        "format": EXPORT_FORMAT,
        "state": state,
        "project_id": revision.project_id,
        "version": revision.version,
        "bundle_format": BUNDLE_FORMAT,
        "bundle_sha256": digest(raw),
        "bundle_bytes": len(raw),
        "source_artifacts": [sources[sha] for sha in sorted(sources)],
        "source_states": sorted(selected_sources, key=lambda part: part["part_id"]),
        "section_hashes": revision.sections,
        "normalizers": {
            "product": baseline.get("normalizer"),
            "parts": {
                part["part_id"]: part.get("baseline", {}).get("normalizer")
                for part in inventory.get("assembly", {}).get("parts", [])
            },
        },
        "integrity": "content_digest_only_not_authenticity_or_approval",
    }
    return raw, manifest


def build_vscorer_worklist(journal, state):
    """Context-preserving worklist requiring an explicit native VScorer adapter.

    Competing original Base assertions require selection. Published environmental
    scores never become new Base inputs. The existing strict `cves` upload format
    cannot carry this contextual envelope and is not silently impersonated.
    """
    bundle = build_bundle(journal, state)
    items = []
    for finding in bundle["findings"]:
        assertions = []
        for rating in finding["source_ratings"]:
            fact = base_fact(rating.get("vector", ""), rating.get("score"))
            if fact:
                assertions.append(
                    {
                        "original_rating": rating,
                        "base": fact,
                        "vscorer_supported": fact["version"] in {"3.0", "3.1", "4.0"},
                    }
                )
        distinct = {entry["base"]["vector"] for entry in assertions if entry["vscorer_supported"]}
        items.append(
            {
                "finding_id": finding["id"],
                "context_id": finding["context_id"],
                "component_ref": finding["context"]["component_ref"],
                "root_ref": finding["context"]["root_ref"],
                "vulnerability_id": finding["vulnerability_id"],
                "component": finding["component"],
                "context": finding["context"],
                "description": finding["description"],
                "descriptions": finding["descriptions"],
                "sourcefacts": finding["sourcefacts"],
                "source_ratings": finding["source_ratings"],
                "source_base_assertions": assertions,
                "base_selection": "required"
                if len(distinct) > 1
                else "available"
                if distinct
                else "unavailable",
                "published_contextual_score": finding["published_score"],
                "environmental_proposals": finding["evidence"],
                "coverage": finding["coverage"],
            }
        )
    result = {
        "format": WORKLIST_FORMAT,
        "state": state,
        "project_id": bundle["project_id"],
        "version": bundle["version"],
        "items": items,
        "uncontextualized_source_findings": bundle["uncontextualized_source_findings"],
        "limitations": [
            *bundle["limitations"],
            "Native contextual worklist; an explicit VScorer intake adapter is required.",
            "No Base assertion is automatically selected; unsupported ratings remain source evidence.",
        ],
    }
    if "pipeline_context" in bundle:
        result["pipeline_context"] = bundle["pipeline_context"]
    return result


def contextual_pipeline_metadata(bundle, context_id):
    """Exact-context model declarations; external identities are never inferred."""
    full = bundle.get("pipeline_context")
    if full is None:
        return None
    rows = [row for row in full["rows"] if row["context_id"] == context_id]
    model_ids = {mapping["model_id"] for row in rows for mapping in row["mappings"]}
    content = {
        "format": "dtvp.pipeline-context-input/1",
        "inventory_state": full["inventory_state"],
        "configuration_state": full["configuration_state"],
        "context_id": context_id,
        "assurance": full["assurance"],
        "models": [
            model for model in full["configuration"]["models"] if model["model_id"] in model_ids
        ],
        "rows": rows,
        "unmapped": sum(row["status"] == "unmapped" for row in rows),
        "limitations": [
            "Declared model revisions/digests are unverified user/CI assertions.",
            "Entity IDs and legacy names remain explicit; no name-to-GUID conversion occurs.",
            "Missing mappings do not establish a safe or unaffected context.",
        ],
    }
    return {**content, "digest": digest(canonical(content))}
