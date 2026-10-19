"""Coordinator publication after current reviews, with original Base facts retained."""

from pydantic import Field

from dtvp.knowledge.assessments import Target, coverage_status
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha, Update
from dtvp.rescoring import calculate, original_vectors
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class ScoreInput(RequestModel):
    request_id: Name
    expected_versions: dict[Name, Sha]
    targets: list[Target] = Field(min_length=1, max_length=200)
    base_vector: str = Field(min_length=1, max_length=1024)
    vector: str = Field(min_length=1, max_length=1024)
    rationale: str = Field(min_length=1, max_length=6000)


class ScorePublication(ScoreInput):
    preview: Sha


def score_key(context_id, vulnerability_id):
    return "score:" + digest(canonical([context_id, vulnerability_id]))


def review_gate(
    journal,
    sections,
    version,
    vulnerability_id,
    *,
    fingerprint_resolver=None,
    continuity_resolver=None,
):
    if continuity_resolver is None:
        from dtvp.knowledge.assessment_continuity import ApprovalContinuityResolver

        continuity_resolver = ApprovalContinuityResolver(journal, sections, version)
    findings = [
        item
        for item in sections["vulnerabilities"].values()
        if item.get("identifier") == vulnerability_id
    ]
    refs = {item["ref"] for item in findings}
    contexts = [
        item
        for key, item in sections["ownership"].items()
        if key.startswith("context:") and item["component_ref"] in refs
    ]
    missing_refs = refs - {item["component_ref"] for item in contexts}
    missing, pins = [], []
    for context in sorted(contexts, key=lambda item: item["id"]):
        coverage = coverage_status(
            journal,
            sections,
            version,
            context["id"],
            vulnerability_id,
            fingerprint_resolver=fingerprint_resolver,
            continuity_resolver=continuity_resolver,
        )
        if coverage["status"] != "approved" or context["status"] != "resolved":
            missing.append(
                {
                    "context_id": context["id"],
                    "team_id": context.get("team_id"),
                    "status": coverage["status"],
                    "ownership": context["status"],
                }
            )
        else:
            pins.append(
                {
                    "context_id": context["id"],
                    "fingerprint": coverage.get("fingerprint"),
                    "assessment_revision": coverage.get("assessment_revision"),
                    "review": coverage.get("review"),
                }
            )
    return {
        "ready": bool(contexts) and not missing and not missing_refs,
        "missing": missing,
        "unresolved_components": sorted(missing_refs),
        "digest": digest(canonical(pins)),
        "required_contexts": len(contexts),
    }


def prepare_score(journal, *, project_id, data):
    from dtvp.knowledge.workspace import load_sections

    targets = [target.model_dump() for target in data.targets]
    if len({canonical(target) for target in targets}) != len(targets):
        raise ValueError("Scoring targets must be distinct")
    versions = {target.version for target in data.targets}
    if versions != data.expected_versions.keys():
        raise ValueError("Expected versions must match scoring coverage exactly")
    calculated = calculate(data.base_vector, data.vector)
    states = {}
    gates, failures = {}, []
    for version in sorted(versions):
        ref = Ref(project_id=project_id, name=version)
        state = journal.resolve(ref)
        if not state or state != data.expected_versions[version]:
            raise Conflict("Version changed; reload before contextual scoring")
        states[version] = load_sections(journal, state)
    for target in data.targets:
        sections = states[target.version]
        context = sections["ownership"].get("context:" + target.context_id)
        findings = [
            item
            for item in sections["vulnerabilities"].values()
            if context
            and item.get("identifier") == target.vulnerability_id
            and item["ref"] == context["component_ref"]
        ]
        facts = original_vectors([item["advisory"] for item in findings])
        if not findings or calculated["base_vector"] not in {item["vector"] for item in facts}:
            raise ValueError("Scoring requires an original Base vector of this exact occurrence")
        key = (target.version, target.vulnerability_id)
        if key not in gates:
            gates[key] = review_gate(journal, sections, *key)
        if not gates[key]["ready"]:
            failures.append(
                {
                    "version": target.version,
                    "vulnerability_id": target.vulnerability_id,
                    **gates[key],
                }
            )
    content = data.model_dump(mode="json", exclude={"preview"})
    preview = digest(
        canonical(
            [
                "contextual-score.preview/1",
                project_id,
                content,
                calculated,
                [[*key, gate] for key, gate in sorted(gates.items())],
            ]
        )
    )
    return (
        {"preview": preview, "eligible": not failures, "proposal": calculated, "blocked": failures},
        states,
        gates,
    )


def publish_score(
    journal, *, project_id, actor_id, data, provenance=None, publication_fingerprint=None, checks=()
):
    fingerprint = digest(
        canonical(
            ["contextual-score.publish/1", project_id, actor_id, data.model_dump(mode="json")]
        )
    )
    if publication_fingerprint is not None:
        fingerprint = publication_fingerprint
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    preview, states, gates = prepare_score(journal, project_id=project_id, data=data)
    if preview["preview"] != data.preview:
        raise Conflict("Scoring preview changed; preview against current inputs")
    if not preview["eligible"]:
        raise Conflict("All required contexts for this vulnerability must be currently approved")
    updates = []
    for target in data.targets:
        state = states[target.version]
        record = {
            "format": "dtvp.contextual-score/1",
            "actor_id": actor_id,
            "target": target.model_dump(),
            "proposal": preview["proposal"],
            "rationale": data.rationale,
            "coverage_digest": gates[target.version, target.vulnerability_id]["digest"],
        }
        if provenance is not None:
            record["provenance"] = provenance
        state["scoring"][score_key(target.context_id, target.vulnerability_id)] = record
    for version, sections in states.items():
        parent = data.expected_versions[version]
        before = journal.state(parent)
        target = journal.snapshot(
            project_id=project_id,
            version=version,
            actor_id=actor_id,
            reason="Publish coordinator contextual score",
            sections=sections,
            parents=[parent],
            artifacts=before.artifacts,
        )
        updates.append(
            Update(ref=Ref(project_id=project_id, name=version), expected=parent, target=target)
        )
    return journal.publish(
        request_id=request_id, fingerprint=fingerprint, updates=updates, checks=checks
    )


def published_score(journal, sections, version, context_id, vulnerability_id, *, gate=None):
    record = sections["scoring"].get(score_key(context_id, vulnerability_id))
    if not record or record.get("target") != {
        "version": version,
        "context_id": context_id,
        "vulnerability_id": vulnerability_id,
    }:
        return None
    gate = gate if gate is not None else review_gate(journal, sections, version, vulnerability_id)
    return {
        **record["proposal"],
        **({"provenance": record["provenance"]} if "provenance" in record else {}),
        "rationale": record["rationale"],
        "actor_id": record["actor_id"],
        "current": gate["ready"] and gate["digest"] == record["coverage_digest"],
    }
