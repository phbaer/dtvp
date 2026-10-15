"""Explicit, isolated synthetic knowledge workflow. Never mounted in production.

Fixture decisions use the existing named playground personas, not real users.
Build through real domain services in a temporary journal, then publish the whole
fixture atomically. Repeating this operation never resets interactive changes.
"""

import copy
import fcntl
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from dtvp.api import DB, Auth
from dtvp.auth import capabilities
from dtvp.knowledge.assessments import (
    AssessmentInput,
    ReviewInput,
    Target,
    create_review,
    load_sections,
    save_assessment,
)
from dtvp.knowledge.journal import Conflict, Journal, Ref, Update
from dtvp.knowledge.ownership import OwnershipInput, product_heads, update_policy
from dtvp.knowledge.projection import catch_up
from dtvp.knowledge.service import create_tag, import_inventory
from dtvp.models import Grant, Membership, Project, User, Workspace
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

router = APIRouter(prefix="/api/v3/playground/knowledge")
PROJECT_NAME = "Knowledge Workflow Playground"
FIXTURE = "knowledge-workflow/1"
SPECIALIST_PROJECT_NAME = "Knowledge Specialist Playground"
SPECIALIST_FIXTURE = "knowledge-specialists/1"
VERSIONS = ("7.1.1", "7.1.2")
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def document(version):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "product",
                "name": "Synthetic workflow product",
                "version": version,
            }
        },
        "components": [
            {
                "type": "application" if ref.endswith("app") else "library",
                "bom-ref": ref,
                "name": ref,
                "version": "1.0",
                "purl": f"pkg:generic/{ref}@1.0",
            }
            for ref in ("platform-app", "operations-app", "shared-tls", "shared-parser")
        ],
        "dependencies": [
            {"ref": "product", "dependsOn": ["platform-app", "operations-app"]},
            {"ref": "platform-app", "dependsOn": ["shared-tls", "shared-parser"]},
            {"ref": "operations-app", "dependsOn": ["shared-tls", "shared-parser"]},
            {"ref": "shared-tls", "dependsOn": []},
            {"ref": "shared-parser", "dependsOn": []},
        ],
        "vulnerabilities": [
            {
                "id": identifier,
                "description": description,
                "source": {"name": "Synthetic workflow evidence"},
                "ratings": [{"method": "CVSSv31", "score": 9.8, "vector": VECTOR}],
                "affects": [{"ref": ref}],
            }
            for identifier, ref, description in (
                (
                    "CVE-2099-31001",
                    "shared-tls",
                    "Synthetic TLS defect. Determine whether the vulnerable protocol is enabled in each consuming application.",
                ),
                (
                    "CVE-2099-31002",
                    "shared-parser",
                    "Synthetic parser defect. Review whether untrusted input reaches this parser and retain deployment evidence.",
                ),
            )
        ],
    }


def fixture_users(db, *, specialists=False):
    subjects = ("administrator", "analyst", "reviewer", "operations", "operations-reviewer")
    if specialists:
        subjects = (*subjects, "license-analyst")
    users = {
        user.subject: user
        for user in db.scalars(
            select(User).where(User.issuer == "playground", User.subject.in_(subjects))
        )
    }
    teams = {
        team.name: team.id
        for team in db.scalars(
            select(Workspace).where(Workspace.name.in_(["Platform", "Operations"]))
        )
    }
    if set(users) != set(subjects) or set(teams) != {"Platform", "Operations"}:
        raise HTTPException(409, "The standard playground personas and teams are required")
    return users, teams


def authorize_fixture(db, project, user):
    """Apply actual memberships and sharing to server-selected synthetic actors."""

    def authorize(team_id, capability):
        member = db.get(Membership, (team_id, user.id))
        grant = db.get(Grant, (project.id, team_id))
        if not member or capability not in capabilities(member.roles):
            raise PermissionError("Synthetic persona lacks the required team role")
        if team_id != project.workspace_id and (not grant or capability not in grant.capabilities):
            raise PermissionError("Synthetic persona lacks project sharing")

    return authorize


def build_fixture(journal, db, project, users, teams, *, specialists=False):
    def fixture_document(version):
        value = document(version)
        if specialists:
            value["components"][2]["licenses"] = [{"license": {"id": "MIT"}}]
            value["components"][2]["properties"] = [
                {"name": "vscorer:threat-model-element-ids", "value": "synthetic-tls-boundary"}
            ]
            value["components"][3]["licenses"] = [{"expression": "Apache-2.0"}]
        return value

    qualified = (
        {
            "analysis_source": {"repository_name": "synthetic-workflow", "source_commit": "a" * 40},
            "subject_digest": "sha256:" + "b" * 64,
        }
        if specialists
        else {}
    )

    admin = users["administrator"].id
    for version in VERSIONS:
        import_inventory(
            journal,
            project_id=project.id,
            version=version,
            actor_id=admin,
            request_id=f"fixture-import-{version}",
            expected=None,
            source="playground:knowledge-workflow",
            build_number=1,
            occurred_at="2026-01-01T00:00:00+00:00",
            sbom=fixture_document(version),
            context={
                **qualified,
                "subject_kind": "build",
                "configuration": "synthetic",
                "pipeline_run": "fixture-1",
                "collector": "DTVP playground",
                "method": "build",
                "limitations": [
                    "Synthetic composition and decisions; not a real assessment or release."
                ],
            },
        )
    update_policy(
        journal,
        project_id=project.id,
        actor_id=admin,
        data=OwnershipInput(
            request_id="fixture-ownership",
            expected_policy=None,
            expected_versions=product_heads(journal.references(), project.id),
            rules=[
                {"selector": "platform-app", "team_id": teams["Platform"]},
                {"selector": "operations-app", "team_id": teams["Operations"]},
            ],
            context_roots={version: ["platform-app", "operations-app"] for version in VERSIONS},
        ),
    )

    def head(version):
        return journal.resolve(Ref(project_id=project.id, name=version))

    def assess(
        version, root, component, identifier, persona, assessment_id, *, approve=False, draft=False
    ):
        state = head(version)
        sections = load_sections(journal, state)
        context = next(
            value
            for key, value in sections["ownership"].items()
            if key.startswith("context:")
            and value["root_ref"] == root
            and value["component_ref"] == component
        )
        target = Target(version=version, context_id=context["id"], vulnerability_id=identifier)
        user = users[persona]
        save_assessment(
            journal,
            project_id=project.id,
            actor_id=user.id,
            assessment_id=assessment_id,
            data=AssessmentInput(
                request_id=assessment_id,
                expected_versions={version: state},
                expected_revision=None,
                targets=[target],
                state="not_affected",
                justification="code_not_reachable",
                rationale="Synthetic deployment evidence: this application's configuration excludes the vulnerable execution path. Verify the equivalent evidence for a real product.",
                evidence=[
                    {
                        "source": "synthetic-playground",
                        "description": "Example deployment report; no real security conclusion.",
                    }
                ],
            ),
            submit=not draft,
            authorize=authorize_fixture(db, project, user),
        )
        if approve:
            state = head(version)
            record = load_sections(journal, state)["assessments"]["assessment:" + assessment_id]
            reviewer = users["reviewer" if persona == "analyst" else "operations-reviewer"]
            create_review(
                journal,
                project_id=project.id,
                actor_id=reviewer.id,
                data=ReviewInput(
                    request_id=assessment_id + "-review",
                    expected_versions={version: state},
                    assessment_id=assessment_id,
                    assessment_revision=record["revision"],
                    targets=[target],
                    action="approve",
                    rationale="Synthetic independent review confirms the example scope and deployment evidence.",
                ),
                authorize=authorize_fixture(db, project, reviewer),
            )

    assess(
        VERSIONS[0],
        "platform-app",
        "shared-parser",
        "CVE-2099-31002",
        "analyst",
        "fixture-earlier-draft",
        draft=True,
    )
    assess(
        VERSIONS[1],
        "platform-app",
        "shared-tls",
        "CVE-2099-31001",
        "analyst",
        "fixture-approved-tls",
        approve=True,
    )
    assess(
        VERSIONS[1],
        "operations-app",
        "shared-tls",
        "CVE-2099-31001",
        "operations",
        "fixture-submitted-tls",
    )
    assess(
        VERSIONS[1],
        "platform-app",
        "shared-parser",
        "CVE-2099-31002",
        "analyst",
        "fixture-stale-parser",
        approve=True,
    )
    create_tag(
        journal,
        project_id=project.id,
        actor_id=admin,
        name="workflow-demo-reviewed-baseline",
        state=head(VERSIONS[1]),
        request_id="fixture-historical-tag",
    )
    changed = copy.deepcopy(fixture_document(VERSIONS[1]))
    changed["vulnerabilities"][1]["description"] += (
        " Updated supplier evidence identifies another potentially reachable entry point; reassessment is required."
    )
    import_inventory(
        journal,
        project_id=project.id,
        version=VERSIONS[1],
        actor_id=admin,
        request_id="fixture-evidence-update",
        expected=head(VERSIONS[1]),
        source="playground:knowledge-workflow",
        build_number=2,
        occurred_at="2026-01-02T00:00:00+00:00",
        sbom=changed,
        context={
            **qualified,
            "subject_kind": "build",
            "configuration": "synthetic",
            "pipeline_run": "fixture-2",
            "collector": "DTVP playground",
            "method": "build",
            "limitations": [
                "Synthetic composition and decisions; not a real assessment or release."
            ],
        },
    )


def build_specialist_evidence(journal, db, project, users):
    """Synthetic reports exercise real contracts, never external integrations."""
    from dtvp.knowledge.agentyzer import derive_analysis_input
    from dtvp.knowledge.agentyzer_results import AgentyzerResultInput, import_agentyzer_result
    from dtvp.knowledge.license_reviews import LicenseInput, save_license
    from dtvp.knowledge.proposals import VScorerProposalInput, import_vscorer_proposal
    from dtvp.knowledge.vscorer import derive_context_inputs
    from dtvp.rescoring import calculate

    version = VERSIONS[1]
    identifier = "CVE-2099-31001"
    actor = users["analyst"]

    def head():
        return journal.resolve(Ref(project_id=project.id, name=version))

    context = next(
        value
        for key, value in load_sections(journal, head())["ownership"].items()
        if key.startswith("context:")
        and value["root_ref"] == "platform-app"
        and value["component_ref"] == "shared-tls"
    )
    license_actor = users["license-analyst"]
    save_license(
        journal,
        project_id=project.id,
        version=version,
        actor_id=license_actor.id,
        data=LicenseInput(
            request_id="synthetic-license-disposition",
            expected=head(),
            expected_revision=None,
            component_ref="shared-tls",
            concluded_expression="MIT",
            disposition="allowed",
            obligations=["Synthetic example: retain the copyright and license notice."],
            distribution="Synthetic example distribution only",
            modification="Unmodified example",
            linking="Synthetic dynamic linking assumption",
            rationale="Demonstration judgment only; no real legal clearance or compliance conclusion.",
            provenance={"source": "synthetic-playground"},
            evidence=[
                {
                    "source": "synthetic-playground",
                    "description": "Invented MIT evidence for interaction testing.",
                }
            ],
        ),
        submit=True,
        authorize=lambda capability: authorize_fixture(db, project, license_actor)(
            project.workspace_id, capability
        ),
    )
    derived = derive_context_inputs(
        journal, head(), context["id"], "shared-tls", {identifier: VECTOR}
    )
    receipt = derived["dtvp_source"]
    binding = {
        "receipt": receipt,
        "receipt_sha256": digest(canonical(receipt)),
        "verification": "artifact_scope_and_base_consistency",
        "remote_authenticity": "not_verified",
    }
    fragment = {key: value for key, value in receipt.items() if key != "selected_source_base"} | {
        "selected_source_base": receipt["selected_source_base"],
        "receipt_sha256": binding["receipt_sha256"],
        "verification": binding["verification"],
        "remote_authenticity": "not_verified",
    }
    contextual = VECTOR + "/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:N/MA:N"
    import_vscorer_proposal(
        journal,
        project_id=project.id,
        version=version,
        actor_id=actor.id,
        data=VScorerProposalInput(
            request_id="synthetic-vscorer-proposal",
            expected=head(),
            source_binding=binding,
            source_label="Synthetic VScorer playground",
            finding={
                "id": "synthetic-vscorer-finding",
                "cve_id": identifier,
                "state": "pending",
                "source_facts": {
                    "dtvp_source": fragment,
                    "base_vector": VECTOR,
                    "base_score": 9.8,
                    "components": [{"bom_ref": "shared-tls"}],
                },
                "preview": {
                    "environmental_vector": contextual,
                    "environmental_score": calculate(VECTOR, contextual)["score"],
                    "environmental_approval_allowed": True,
                    "approval_blockers": [],
                },
                "rationale": "Synthetic threat-model proposal; no external VScorer call or verified provider.",
            },
        ),
    )
    analysis = derive_analysis_input(journal, head(), context["id"], identifier)
    import_agentyzer_result(
        journal,
        project_id=project.id,
        version=version,
        actor_id=actor.id,
        data=AgentyzerResultInput(
            request_id="synthetic-agentyzer-evidence",
            expected=head(),
            input_receipt=analysis["receipt"],
            source_label="Synthetic Agentyzer playground",
            raw_report={
                "assessment": {
                    "affected": None,
                    "confidence": "Low",
                    "summary": "Synthetic source-analysis example, not an actual repository analysis.",
                    "reasoning": "No external call, code scan, provider verification or binary/build verification occurred.",
                    "application_eligible": False,
                    "rescoring_eligible": False,
                }
            },
        ),
    )


class SeedInput(RequestModel):
    scenario: Literal["workflow", "specialists"] = "workflow"


@router.post("/seed")
def seed_knowledge(data: SeedInput, request: Request, db: DB, actor: Auth):
    if not request.app.state.settings.playground:
        raise HTTPException(404)
    journal = request.app.state.knowledge
    specialists = data.scenario == "specialists"
    project_name = SPECIALIST_PROJECT_NAME if specialists else PROJECT_NAME
    fixture = SPECIALIST_FIXTURE if specialists else FIXTURE
    # Separate from the journal writer lock: domain services acquire that lock.
    with (journal.root / "playground-seed.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        users, teams = fixture_users(db, specialists=specialists)
        project = db.scalar(
            select(Project).where(
                Project.workspace_id == teams["Platform"], Project.name == project_name
            )
        )
        if project and project.metadata_json.get("playground_fixture") != fixture:
            raise HTTPException(409, "A non-fixture project already uses the demo name")
        if not project:
            project = Project(
                workspace_id=teams["Platform"],
                name=project_name,
                metadata_json={"playground_fixture": fixture, "synthetic": True},
            )
            db.add(project)
            db.flush()
            db.add(
                Grant(
                    project_id=project.id,
                    workspace_id=teams["Operations"],
                    capabilities=["read", "assess", "approve"],
                )
            )
            # Keep published journal references attached to durable access metadata.
            db.commit()
        current = product_heads(journal.references(), project.id)
        preserved_existing = bool(current)
        if not current:
            with TemporaryDirectory(prefix="knowledge-fixture-", dir=journal.root) as folder:
                staging = Journal(Path(folder))
                build_fixture(staging, db, project, users, teams, specialists=specialists)
                if specialists:
                    build_specialist_evidence(staging, db, project, users)
                refs = staging.references()
                for path in staging.objects.root.glob("*/*"):
                    journal.objects.put(staging.objects.read(path.parent.name + path.name))
                updates = [
                    Update(ref=Ref.model_validate_json(key), expected=None, target=state)
                    for key, state in sorted(refs.items())
                ]
                try:
                    journal.publish(
                        request_id=digest(canonical([fixture, project.id])),
                        fingerprint=digest(canonical(refs)),
                        updates=updates,
                    )
                except Conflict as error:
                    raise HTTPException(409, str(error)) from error
            current = product_heads(journal.references(), project.id)
    catch_up(request.app.state.engine, journal)
    return {
        "project_id": project.id,
        "project_name": project.name,
        "version": VERSIONS[1] if VERSIONS[1] in current else sorted(current)[-1],
        "synthetic": True,
        "scenario": data.scenario,
        "preserved_existing": preserved_existing,
    }
