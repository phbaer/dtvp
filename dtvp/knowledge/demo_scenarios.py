"""Fixed synthetic demo phases driven by editable scenario data, never scripts."""

from typing import Literal

from pydantic import Field, model_validator

from dtvp.knowledge.assessments import (
    AssessmentInput,
    ReviewInput,
    Target,
    create_review,
    load_sections,
    save_assessment,
)
from dtvp.knowledge.composition import CollectionContext
from dtvp.knowledge.evidence_conformance import bounded_tree
from dtvp.knowledge.journal import Name, Ref, Update
from dtvp.knowledge.ownership import OwnershipInput, product_heads, update_policy
from dtvp.knowledge.service import create_tag, import_inventory
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_SCENARIO_BYTES = 32 * 1024 * 1024
Persona = Literal[
    "administrator", "analyst", "reviewer", "operations", "operations-reviewer", "license-analyst"
]


class ScenarioImport(RequestModel):
    id: Name
    version: Name
    source: Name
    build_number: int = Field(ge=0, strict=True)
    occurred_at: str
    sbom: dict
    context: CollectionContext


class ScenarioRule(RequestModel):
    selector: Name
    team: Literal["Platform", "Operations"]


class ScenarioOwnership(RequestModel):
    rules: list[ScenarioRule] = Field(max_length=100)
    context_roots: dict[Name, list[Name]]


class ScenarioReview(RequestModel):
    persona: Persona
    rationale: str = Field(min_length=1, max_length=6000)


class ScenarioTarget(RequestModel):
    id: Name
    version: Name
    root_ref: Name
    component_ref: Name
    vulnerability_id: Name
    persona: Persona


class ScenarioAssessment(ScenarioTarget):
    stage: Literal["draft", "submitted", "approved"]
    assessment: dict
    review: ScenarioReview | None = None

    @model_validator(mode="after")
    def exact_fields(self):
        if set(self.assessment) - {
            "state",
            "justification",
            "rationale",
            "conditions",
            "evidence",
            "ssvc",
        }:
            raise ValueError("Assessment data cannot override server-owned pins or actors")
        if (self.stage == "approved") != bool(self.review):
            raise ValueError("Approved synthetic assessments require an explicit reviewer")
        return self


class ScenarioTag(RequestModel):
    name: Name
    version: Name


class ScenarioLicense(RequestModel):
    id: Name
    version: Name
    component_ref: Name
    persona: Persona
    submit: bool
    disposition: dict

    @model_validator(mode="after")
    def exact_fields(self):
        from dtvp.knowledge.license_reviews import LicenseInput

        if set(self.disposition) - (
            set(LicenseInput.model_fields)
            - {"request_id", "expected", "expected_revision", "component_ref"}
        ):
            raise ValueError("License data cannot override server-owned pins or actors")
        return self


class ScenarioVScorer(ScenarioTarget):
    source_label: Name
    base_vector: str = Field(max_length=2000)
    binding_reason: str = Field(min_length=1, max_length=6000)
    finding: dict


class ScenarioAnalysis(ScenarioTarget):
    source_label: Name
    report: dict


class DemoScenario(RequestModel):
    format: Literal["dtvp.demo-scenario/1"]
    synthetic: Literal[True]
    fixture_id: Name
    project_name: Name
    selected_version: Name
    baselines: list[ScenarioImport] = Field(min_length=1, max_length=10)
    ownership: ScenarioOwnership
    assessments: list[ScenarioAssessment] = Field(default_factory=list, max_length=100)
    tags: list[ScenarioTag] = Field(default_factory=list, max_length=20)
    updates: list[ScenarioImport] = Field(default_factory=list, max_length=50)
    licenses: list[ScenarioLicense] = Field(default_factory=list, max_length=100)
    vscorer_proposals: list[ScenarioVScorer] = Field(default_factory=list, max_length=100)
    code_analysis: list[ScenarioAnalysis] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def coherent(self):
        data = self.model_dump(mode="json")
        bounded_tree(data)
        if len(canonical(data)) > MAX_SCENARIO_BYTES:
            raise ValueError("Demo scenario exceeds 32 MiB")
        versions = [item.version for item in self.baselines]
        if len(versions) != len(set(versions)) or self.selected_version not in versions:
            raise ValueError("Baseline versions must be distinct and include the selected version")
        if set(self.ownership.context_roots) - set(versions):
            raise ValueError("Ownership roots name a version without a baseline")
        items = [
            *self.baselines,
            *self.updates,
            *self.assessments,
            *self.licenses,
            *self.vscorer_proposals,
            *self.code_analysis,
        ]
        identifiers = [item.id for item in items]
        if (
            len(identifiers) != len(set(identifiers))
            or any(item.version not in versions for item in items)
            or any(tag.version not in versions for tag in self.tags)
        ):
            raise ValueError(
                "Scenario operation IDs must be distinct and versions must have baselines"
            )
        return self


def build_scenario(journal, db, project, users, teams, data, authorize):
    """Run a fixed domain workflow, staging all changes before live publication."""
    admin = users["administrator"].id

    def head(version):
        return journal.resolve(Ref(project_id=project.id, name=version))

    artifact = journal.objects.put(canonical(data.model_dump(mode="json")))

    def mark_synthetic(version, operation):
        previous = head(version)
        sections = load_sections(journal, previous)
        sections["history"]["synthetic-scenario"] = {
            "format": data.format,
            "synthetic": True,
            "fixture_id": data.fixture_id,
            "scenario_sha256": artifact,
            "actors": "named synthetic playground personas",
            "human_approval_assurance": "simulated fixture decisions only",
        }
        revision = journal.snapshot(
            project_id=project.id,
            version=version,
            actor_id=admin,
            reason="Load explicit synthetic scenario",
            sections=sections,
            parents=[previous],
            artifacts=sorted(set(journal.state(previous).artifacts) | {artifact}),
        )
        journal.publish(
            request_id=digest(canonical([data.fixture_id, version, operation])),
            fingerprint=revision,
            updates=[
                Update(
                    ref=Ref(project_id=project.id, name=version), expected=previous, target=revision
                )
            ],
        )

    def imported(item):
        import_inventory(
            journal,
            project_id=project.id,
            version=item.version,
            actor_id=admin,
            request_id=item.id,
            expected=head(item.version),
            source=item.source,
            build_number=item.build_number,
            occurred_at=item.occurred_at,
            sbom=item.sbom,
            context=item.context.model_dump(mode="json"),
            source_provenance={
                "synthetic": True,
                "fixture_id": data.fixture_id,
                "scenario_sha256": artifact,
                "human_approval_assurance": "simulated fixture decisions only",
            },
            additional_artifacts=(artifact,),
        )
        mark_synthetic(item.version, "import-" + item.id)

    def context(item):
        matches = [
            value
            for key, value in load_sections(journal, head(item.version))["ownership"].items()
            if key.startswith("context:")
            and value["root_ref"] == item.root_ref
            and value["component_ref"] == item.component_ref
        ]
        if len(matches) != 1:
            raise ValueError("Synthetic target must select exactly one consuming context")
        return matches[0]

    for item in data.baselines:
        imported(item)
    update_policy(
        journal,
        project_id=project.id,
        actor_id=admin,
        data=OwnershipInput(
            request_id="scenario-ownership",
            expected_policy=None,
            expected_versions=product_heads(journal.references(), project.id),
            rules=[
                {"selector": rule.selector, "team_id": teams[rule.team]}
                for rule in data.ownership.rules
            ],
            context_roots=data.ownership.context_roots,
        ),
    )
    for item in data.assessments:
        target = Target(
            version=item.version,
            context_id=context(item)["id"],
            vulnerability_id=item.vulnerability_id,
        )
        user = users[item.persona]
        save_assessment(
            journal,
            project_id=project.id,
            actor_id=user.id,
            assessment_id=item.id,
            data=AssessmentInput(
                **item.assessment,
                request_id=item.id,
                expected_versions={item.version: head(item.version)},
                expected_revision=None,
                targets=[target],
            ),
            submit=item.stage != "draft",
            authorize=authorize(db, project, user),
        )
        if item.review:
            record = load_sections(journal, head(item.version))["assessments"][
                "assessment:" + item.id
            ]
            reviewer = users[item.review.persona]
            create_review(
                journal,
                project_id=project.id,
                actor_id=reviewer.id,
                data=ReviewInput(
                    request_id=item.id + "-review",
                    expected_versions={item.version: head(item.version)},
                    assessment_id=item.id,
                    assessment_revision=record["revision"],
                    targets=[target],
                    action="approve",
                    rationale=item.review.rationale,
                ),
                authorize=authorize(db, project, reviewer),
            )
    for index, tag in enumerate(data.tags):
        create_tag(
            journal,
            project_id=project.id,
            actor_id=admin,
            name=tag.name,
            state=head(tag.version),
            request_id=f"scenario-tag-{index}",
        )
    for item in data.updates:
        imported(item)
    for item in data.licenses:
        from dtvp.knowledge.license_reviews import LicenseInput, save_license

        user = users[item.persona]
        save_license(
            journal,
            project_id=project.id,
            version=item.version,
            actor_id=user.id,
            data=LicenseInput(
                **item.disposition,
                request_id=item.id,
                expected=head(item.version),
                expected_revision=None,
                component_ref=item.component_ref,
            ),
            submit=item.submit,
            authorize=lambda capability, user=user: authorize(db, project, user)(
                project.workspace_id, capability
            ),
        )
    for item in data.vscorer_proposals:
        from dtvp.knowledge.issued_exports import issue_export
        from dtvp.knowledge.vscorer import derive_context_inputs
        from dtvp.knowledge.vscorer_minimal import (
            VScorerMinimalProposalInput,
            import_minimal_proposal,
        )

        selected = context(item)
        derived = derive_context_inputs(
            journal,
            head(item.version),
            selected["id"],
            item.component_ref,
            {item.vulnerability_id: item.base_vector},
        )
        issued = issue_export(
            journal,
            project_id=project.id,
            actor_id=users[item.persona].id,
            state=head(item.version),
            kind="vscorer-input",
            payload=derived,
            selector={"context_id": selected["id"]},
        )
        raw = canonical(item.finding)
        import_minimal_proposal(
            journal,
            project_id=project.id,
            version=item.version,
            actor_id=users[item.persona].id,
            data=VScorerMinimalProposalInput(
                request_id=item.id,
                expected=head(item.version),
                issued_input_receipt_sha256=issued["receipt_sha256"],
                input_artifacts={
                    kind: {
                        "artifact_id": "synthetic-" + kind,
                        "sha256": issued["files"][kind + ".json"]["sha256"],
                    }
                    for kind in ("sbom", "cves")
                },
                mapping_mode="not_declared",
                assessment_id=item.finding["assessment_id"],
                finding_json=raw.decode(),
                finding_sha256=digest(raw),
                binding_reason=item.binding_reason,
                source_label=item.source_label,
            ),
        )
    for item in data.code_analysis:
        from dtvp.knowledge.agentyzer import derive_analysis_input
        from dtvp.knowledge.agentyzer_results import AgentyzerResultInput, import_agentyzer_result

        derived = derive_analysis_input(
            journal, head(item.version), context(item)["id"], item.vulnerability_id
        )
        import_agentyzer_result(
            journal,
            project_id=project.id,
            version=item.version,
            actor_id=users[item.persona].id,
            data=AgentyzerResultInput(
                request_id=item.id,
                expected=head(item.version),
                input_receipt=derived["receipt"],
                source_label=item.source_label,
                raw_report=item.report,
            ),
        )

    for version in product_heads(journal.references(), project.id):
        mark_synthetic(version, "scenario-provenance")
