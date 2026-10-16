"""Producer-declared software integration observations and optional offline ancestry proof."""

from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from dtvp.knowledge.comparison import page, product_state, reachable_states
from dtvp.knowledge.composition import AnalysisSource, ArtifactDigest
from dtvp.knowledge.git_ancestry import MAX_OBJECTS, verify_objects
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.service import validate_time
from dtvp.knowledge.synchronization import synchronization_preview
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

FORMAT = "dtvp.integration-event/1"
MAX_REQUEST_BYTES = 12 * 1024 * 1024
Commit = Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
EncodedObject = Annotated[str, Field(max_length=349528)]
LIMITATIONS = [
    "Repository, pipeline, build/artifact correspondence and integration kind are producer declarations, not verified origin or execution.",
    "Only single-baseline product states are supported; one delivery part never establishes whole-product integration.",
    "Target inventory remains authoritative; this observation creates no assessment, review, score, coverage transfer or automatic synchronization basis.",
    "A verified commit-object path establishes hash/parent consistency only, not patch equivalence or assessment applicability.",
]


class IntegrationInput(RequestModel):
    request_id: Name
    source: Sha
    target: Sha
    expected_target: Sha
    repository: Name
    source_commit: Commit
    target_commit: Commit
    target_subject_digest: ArtifactDigest
    pipeline_run: Name
    integration_kind: Literal["merge", "fast_forward", "cherry_pick", "squash", "backport", "other"]
    occurred_at: str
    rationale: str = Field(min_length=1, max_length=2000)
    git_commit_objects: dict[Commit, EncodedObject] = Field(
        default_factory=dict, max_length=MAX_OBJECTS
    )

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value):
        return validate_time(value)

    @field_validator("repository", "pipeline_run", "rationale")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("Integration declarations require meaningful text")
        return value

    @model_validator(mode="after")
    def exact_target(self):
        if self.target != self.expected_target:
            raise ValueError("Integration target must equal the expected branch head")
        return self


class IntegrationPreviewInput(RequestModel):
    target: Sha
    basis: Sha | None = None
    context_mapping: dict[Sha, Sha] = Field(default_factory=dict, max_length=1000)


def _qualified(journal, state, project_id, *, require_subject=False):
    revision = product_state(journal, state, project_id)
    sections = load_sections(journal, state)
    baseline = sections["inventory"]["baseline"]
    if baseline.get("withdrawn"):
        raise ValueError("Integration observation requires an accepted, non-withdrawn baseline")
    if baseline.get("kind") == "assembly" or "assembly" in sections["inventory"]:
        raise ValueError("Integration observation requires a single-baseline product state")
    context = baseline.get("collection", {})
    try:
        source = AnalysisSource.model_validate(context.get("analysis_source"))
    except ValueError, AttributeError:
        raise ValueError("Integration requires producer-qualified repository and commit") from None
    artifact = baseline.get("artifact_sha")
    subject = context.get("subject_digest")
    if (
        not isinstance(artifact, str)
        or not journal.objects.path(artifact).is_file()
        or (require_subject and not subject)
    ):
        raise ValueError(
            "Integration requires retained SBOM bytes and an exact producer-declared subject digest"
        )
    journal.objects.read(artifact)
    return (
        revision,
        sections,
        {
            "repository": source.repository_name,
            "commit": source.source_commit,
            "subject_digest": subject,
            "sbom_artifact_sha256": artifact,
            "pipeline_run": context.get("pipeline_run"),
        },
    )


def event_identity(project_id, actor_id, data):
    identifier = digest(canonical(["integration-event/1", project_id, actor_id, data.request_id]))
    fingerprint = digest(canonical([FORMAT, project_id, actor_id, data.model_dump(mode="json")]))
    return identifier, fingerprint


def record_integration(journal, *, project_id, actor_id, data):
    event_id, fingerprint = event_identity(project_id, actor_id, data)
    with journal.writer():
        receipt = journal.receipt(event_id, fingerprint)
    if receipt:
        return receipt
    reachable = reachable_states(journal, project_id)
    if data.source not in reachable or data.target not in reachable:
        raise ValueError("Integration observations require committed states in one product line")
    source_revision, _, source_pin = _qualified(journal, data.source, project_id)
    target_revision, target_sections, target_pin = _qualified(
        journal, data.target, project_id, require_subject=True
    )
    if source_revision.version == target_revision.version:
        raise ValueError("Cascading integration requires distinct product versions")
    target_ref = Ref(project_id=project_id, name=target_revision.version)
    if journal.resolve(target_ref) != data.expected_target:
        raise Conflict("Target branch changed before recording integration")
    if (
        source_pin["repository"] != data.repository
        or target_pin["repository"] != data.repository
        or source_pin["commit"] != data.source_commit
        or target_pin["commit"] != data.target_commit
        or target_pin["subject_digest"] != data.target_subject_digest
    ):
        raise Conflict(
            "Integration declaration differs from exact source/target repository, commit or artifact pins"
        )
    if target_pin["pipeline_run"] != data.pipeline_run:
        raise Conflict("Integration pipeline run differs from the qualified target collection")
    ancestry, objects = verify_objects(
        data.git_commit_objects, data.source_commit, data.target_commit
    )
    event = {
        "format": FORMAT,
        "event_id": event_id,
        "actor_id": actor_id,
        "source": data.source,
        "target": data.target,
        "source_version": source_revision.version,
        "target_version": target_revision.version,
        "source_pin": source_pin,
        "target_pin": target_pin,
        "declaration": data.model_dump(
            mode="json", exclude={"git_commit_objects", "request_id", "expected_target"}
        ),
        "git_ancestry": ancestry,
        "provenance_verification": "producer_declared_not_authenticated",
        "software_integration_verified": False,
        "limitations": LIMITATIONS,
    }
    event["content_digest"] = digest(canonical(event))
    artifacts = set(journal.state(data.target).artifacts) | {
        source_pin["sbom_artifact_sha256"],
        target_pin["sbom_artifact_sha256"],
    }
    for raw in objects.values():
        artifacts.add(journal.objects.put(raw))
    target_sections["history"]["integration-event:" + event_id] = event
    state = journal.snapshot(
        project_id=project_id,
        version=target_revision.version,
        actor_id=actor_id,
        reason="Record producer-declared software integration",
        sections=target_sections,
        parents=[data.target],
        artifacts=sorted(artifacts),
    )
    return journal.publish(
        request_id=event_id,
        fingerprint=fingerprint,
        updates=[Update(ref=target_ref, expected=data.expected_target, target=state)],
    )


def integration_event(journal, project_id, target, event_id):
    if target not in reachable_states(journal, project_id):
        raise ValueError("Integration event view requires committed product history")
    product_state(journal, target, project_id)
    event = load_sections(journal, target)["history"].get("integration-event:" + event_id)
    if not event or event.get("format") != FORMAT or event.get("event_id") != event_id:
        raise ValueError("Integration event is unavailable in the selected target history")
    if event.get("content_digest") != digest(
        canonical({key: value for key, value in event.items() if key != "content_digest"})
    ):
        raise ValueError("Integration event differs from its recorded content")
    return event


def integration_events(journal, project_id, target, offset=0, limit=50):
    if target not in reachable_states(journal, project_id):
        raise ValueError("Integration event view requires committed product history")
    product_state(journal, target, project_id)
    items = [
        value
        for key, value in sorted(load_sections(journal, target)["history"].items())
        if key.startswith("integration-event:")
    ]
    return {"state": target, **page(items, offset, limit), "limitations": LIMITATIONS}


def integration_synchronization_preview(journal, *, project_id, event_id, data, offset=0, limit=50):
    event = integration_event(journal, project_id, data.target, event_id)
    revision, _, target_pin = _qualified(journal, data.target, project_id, require_subject=True)
    if (
        revision.version != event["target_version"]
        or journal.resolve(Ref(project_id=project_id, name=revision.version)) != data.target
    ):
        raise Conflict("Integration synchronization requires the current target branch head")
    if target_pin != event["target_pin"]:
        raise Conflict(
            "Target software/artifact input changed; record a new explicit integration observation"
        )
    result = synchronization_preview(
        journal,
        project_id,
        event["source"],
        data.target,
        data.basis,
        data.context_mapping,
        offset,
        limit,
    )
    return {
        "format": "dtvp.integration-synchronization-preview/1",
        "integration_event": event,
        "basis_selection": "explicit" if data.basis else "none_no_inferred_common_basis",
        "proposals": result,
        "apply_supported": False,
        "limitations": LIMITATIONS,
    }
