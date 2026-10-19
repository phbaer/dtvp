"""Pinned project rules produce explicit coordinator proposals from approved applicability."""

import json
from typing import Literal

from pydantic import Field

from dtvp.cvss_rules import build_rescored_vector_for_state
from dtvp.knowledge.assessments import Target, coverage_status
from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.scoring import ScoreInput, ScorePublication, prepare_score, publish_score
from dtvp.knowledge.workspace import load_sections
from dtvp.rescoring import DEFAULT_PATH, calculate, validate_policy
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class PolicyInput(RequestModel):
    request_id: Name
    expected_policy: Sha | None
    config: dict


class RuleInput(RequestModel):
    request_id: Name
    expected_policy: Sha | None
    expected_versions: dict[Name, Sha]
    targets: list[Target] = Field(min_length=1, max_length=200)
    base_vector: str = Field(min_length=1, max_length=1024)
    vector: str = Field(min_length=1, max_length=1024)
    rationale: str = Field(min_length=1, max_length=6000)
    rule_basis: Literal["applicability", "false_positive"] = "applicability"


class RulePublication(RuleInput):
    preview: Sha


def policy_ref(project_id):
    return Ref(kind="policy", project_id=project_id, name="rescore-rules")


def current_policy(journal, project_id):
    state = journal.resolve(policy_ref(project_id))
    config = (
        journal.load(journal.records(state, "scoring")["configuration"])
        if state
        else json.loads(DEFAULT_PATH.read_text())
    )
    return {"state": state, "digest": digest(canonical(config)), "config": config}


def identity(project_id, actor_id, data, operation):
    return (
        digest(canonical([project_id, actor_id, data.request_id])),
        digest(canonical([operation, project_id, actor_id, data.model_dump(mode="json")])),
    )


def configure_policy(journal, *, project_id, actor_id, data):
    request_id, fingerprint = identity(project_id, actor_id, data, "scoring-policy.configure/1")
    with journal.writer():
        if receipt := journal.receipt(request_id, fingerprint):
            return receipt
    # Reject malformed containers before the retained detailed rule validator.
    validate_config(data.config)
    if journal.resolve(policy_ref(project_id)) != data.expected_policy:
        raise Conflict("Scoring policy changed; reload before configuring")
    sections = {name: {} for name in SECTIONS}
    sections["scoring"]["configuration"] = data.config
    state = journal.snapshot(
        project_id=project_id,
        version="@rescore-rules",
        actor_id=actor_id,
        reason="Configure contextual scoring rules",
        sections=sections,
        parents=[data.expected_policy] if data.expected_policy else [],
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=policy_ref(project_id), expected=data.expected_policy, target=state)],
    )


def validate_config(config):
    if len(canonical(config)) > 256 * 1024:
        raise ValueError("Scoring policy exceeds 256 KiB")
    metric_rules, transitions = config.get("metric_rules"), config.get("transitions")
    if not isinstance(metric_rules, dict) or not isinstance(transitions, list):
        raise ValueError("Scoring policy requires metric_rules and transitions")
    for rule in metric_rules.values():
        if not isinstance(rule, dict):
            raise ValueError("Metric rule must be an object")
        for key in ("undefined_values", "base_metrics", "metric_order"):
            if not isinstance(rule.get(key), list) or not all(
                isinstance(v, str) for v in rule[key]
            ):
                raise ValueError("Metric rule lists must contain strings")
        if not isinstance(rule.get("relationships"), list) or not all(
            isinstance(row, dict) and all(isinstance(v, str) for v in row.values())
            for row in rule["relationships"]
        ):
            raise ValueError("Metric relationships must contain string-valued objects")
    for row in transitions:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("trigger", {}), dict)
            or not isinstance(row.get("actions"), dict)
        ):
            raise ValueError("Transition trigger and actions must be objects")
        trigger = row.get("trigger", {}).get("state", row.get("from"))
        if not isinstance(trigger, str) or not trigger:
            raise ValueError("Transition state must be a nonempty string")
        for actions in row["actions"].values():
            if not isinstance(actions, dict) or not all(
                isinstance(v, str) for v in actions.values()
            ):
                raise ValueError("Transition actions must contain string-valued objects")
    validate_policy(config)


def prepare_rule_score(journal, *, project_id, data):
    configured = current_policy(journal, project_id)
    if configured["state"] != data.expected_policy:
        raise Conflict("Scoring policy changed; preview again")
    calculate(data.base_vector, data.vector)
    states, proofs, applicability = {}, [], set()
    for target in data.targets:
        state = journal.resolve(Ref(project_id=project_id, name=target.version))
        if state != data.expected_versions.get(target.version):
            raise Conflict("Version changed; reload scoring targets")
        if target.version not in states:
            states[target.version] = load_sections(journal, state)
        coverage = coverage_status(
            journal,
            states[target.version],
            target.version,
            target.context_id,
            target.vulnerability_id,
        )
        approved = coverage.get("approved_assessment")
        if coverage["status"] != "approved" or not approved:
            raise Conflict("Rule scoring requires a currently approved target assessment")
        applicability.add(approved["payload"]["state"])
        proofs.append(
            {
                "target": target.model_dump(),
                "assessment_revision": approved["revision"],
                "review": coverage["review"],
            }
        )
    if len(applicability) != 1:
        raise ValueError("Rule targets require compatible approved applicability")
    state = next(iter(applicability))
    trigger = {
        "affected": "EXPLOITABLE",
        "not_affected": "NOT_AFFECTED",
        "fixed": "RESOLVED",
        "under_investigation": "IN_TRIAGE",
    }[state]
    if data.rule_basis == "false_positive":
        if state != "not_affected":
            raise ValueError("False-positive rules require approved not-affected applicability")
        trigger = "FALSE_POSITIVE"
    result = build_rescored_vector_for_state(
        configured["config"],
        state=trigger,
        base_vector=data.base_vector,
        current_vector=data.vector,
    )
    if not result:
        raise ValueError("No rule exists for this approved applicability and CVSS version")
    score = ScoreInput(
        **data.model_dump(exclude={"expected_policy", "rule_basis", "preview", "vector"}),
        vector=result[0],
    )
    preview, _, _ = prepare_score(journal, project_id=project_id, data=score)
    provenance = {
        "kind": "rule",
        "policy_state": configured["state"],
        "policy_digest": configured["digest"],
        "rule_config": configured["config"],
        "rule_basis": data.rule_basis,
        "rule_state": state,
        "trigger": trigger,
        "input_vector": data.vector,
        "approved_assessments": proofs,
    }
    rule_preview = digest(
        canonical(
            [
                "rule-score.preview/1",
                project_id,
                data.model_dump(exclude={"preview"}),
                preview,
                provenance,
            ]
        )
    )
    return {**preview, "preview": rule_preview, "provenance": provenance}, score, preview["preview"]


def publish_rule_score(journal, *, project_id, actor_id, data):
    request_id, fingerprint = identity(project_id, actor_id, data, "rule-score.publish/1")
    with journal.writer():
        if receipt := journal.receipt(request_id, fingerprint):
            return receipt
    preview, score, manual_preview = prepare_rule_score(journal, project_id=project_id, data=data)
    if data.preview != preview["preview"]:
        raise Conflict("Rule scoring preview changed; preview again")
    return publish_score(
        journal,
        project_id=project_id,
        actor_id=actor_id,
        data=ScorePublication(**score.model_dump(), preview=manual_preview),
        provenance=preview["provenance"],
        publication_fingerprint=fingerprint,
        checks=[(policy_ref(project_id), data.expected_policy)],
    )
