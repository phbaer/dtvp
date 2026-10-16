"""Versioned user/CI declarations; matching never authenticates external models."""

from typing import Literal

from pydantic import Field, model_validator

from dtvp.knowledge.comparison import reachable_states
from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.selectors import (
    component_identity,
    parse_team_mapping_key,
    selector_matches_identity,
)
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_CONFIG_BYTES = 2 * 1024 * 1024


class PartSources(RequestModel):
    part_id: Name | None = None
    authority_source: Name
    observation_sources: list[Name] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def distinct(self):
        if (
            len(set(self.observation_sources)) != len(self.observation_sources)
            or self.authority_source in self.observation_sources
        ):
            raise ValueError("Part source roles must be distinct")
        return self


class ModelEntity(RequestModel):
    entity_id: Name
    name: Name
    external: bool = False


class ThreatModel(RequestModel):
    model_id: Name
    revision: Name
    digest_sha256: Sha
    entities: list[ModelEntity] = Field(default_factory=list, max_length=2000)

    @model_validator(mode="after")
    def unique(self):
        if len({entity.entity_id for entity in self.entities}) != len(self.entities):
            raise ValueError("Model entity IDs must be unique")
        return self


class ModelMapping(RequestModel):
    mapping_id: Name
    component_selector: str = Field(min_length=1, max_length=4096)
    context_selector: str | None = Field(default=None, min_length=1, max_length=4096)
    model_id: Name
    entity_ids: list[Name] = Field(min_length=1, max_length=200)
    legacy_names: list[Name] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def valid(self):
        for text in (self.component_selector, self.context_selector):
            if text is not None and parse_team_mapping_key(text).wildcard:
                raise ValueError(
                    "Explicit component selectors required; wildcard mappings are unsupported"
                )
        if len(set(self.entity_ids)) != len(self.entity_ids) or len(set(self.legacy_names)) != len(
            self.legacy_names
        ):
            raise ValueError("Mapping entity IDs and legacy names must be unique")
        return self


class PipelineConfiguration(RequestModel):
    format: Literal["dtvp.pipeline-configuration/1"] = "dtvp.pipeline-configuration/1"
    parts: list[PartSources] = Field(default_factory=list, max_length=200)
    models: list[ThreatModel] = Field(default_factory=list, max_length=100)
    mappings: list[ModelMapping] = Field(default_factory=list, max_length=2000)

    @model_validator(mode="after")
    def consistent(self):
        for rows, key in (
            (self.parts, "part_id"),
            (self.models, "model_id"),
            (self.mappings, "mapping_id"),
        ):
            if len({getattr(row, key) for row in rows}) != len(rows):
                raise ValueError(f"Duplicate {key}")
        models = {
            model.model_id: {entity.entity_id for entity in model.entities} for model in self.models
        }
        for mapping in self.mappings:
            if (
                mapping.model_id not in models
                or not set(mapping.entity_ids) <= models[mapping.model_id]
            ):
                raise ValueError("Mapping references an unknown model or entity")
        if len(canonical(self.model_dump(mode="json"))) > MAX_CONFIG_BYTES:
            raise ValueError("Pipeline configuration exceeds 2 MiB")
        return self


class PipelineConfigInput(PipelineConfiguration):
    request_id: Name
    expected_policy: Sha | None
    expected_versions: dict[Name, Sha] = Field(default_factory=dict, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def meaningful(self):
        if not self.reason.strip():
            raise ValueError("Configuration reason must be meaningful")
        return self


def config_ref(project_id):
    return Ref(kind="policy", project_id=project_id, name="pipeline")


def current_config(journal, project_id):
    state = journal.resolve(config_ref(project_id))
    return (
        (state, retained_config(journal, project_id, state))
        if state
        else (None, PipelineConfiguration().model_dump(mode="json"))
    )


def retained_config(journal, project_id, selected):
    current, seen = journal.resolve(config_ref(project_id)), set()
    while current and current not in seen:
        if len(seen) >= 1000:
            raise ValueError("Pipeline configuration history exceeds 1,000 revisions")
        seen.add(current)
        state = journal.state(current)
        if state.project_id != project_id or state.version != "@pipeline":
            raise ValueError("Inconsistent pipeline configuration lineage")
        if current == selected:
            pointer = journal.records(current, "inventory")["pipeline:configuration"]
            if journal.objects.path(pointer).stat().st_size > MAX_CONFIG_BYTES:
                raise ValueError("Retained pipeline configuration exceeds bound")
            return PipelineConfiguration.model_validate(journal.load(pointer)).model_dump(
                mode="json"
            )
        current = state.parents[0] if state.parents else None
    raise ValueError("Pipeline configuration is not retained in this product line")


def current_heads(journal, project_id):
    return {
        ref.name: sha
        for key, sha in journal.references().items()
        if (ref := Ref.model_validate_json(key)).project_id == project_id and ref.kind == "branch"
    }


def configure(journal, *, project_id, actor_id, data):
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    fingerprint = digest(
        canonical(["pipeline.configure/1", project_id, actor_id, data.model_dump(mode="json")])
    )
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    if (
        journal.resolve(config_ref(project_id)) != data.expected_policy
        or current_heads(journal, project_id) != data.expected_versions
    ):
        raise Conflict(
            "Pipeline configuration or product versions changed; capture current pins again"
        )
    config = PipelineConfiguration.model_validate(
        data.model_dump(include=set(PipelineConfiguration.model_fields))
    ).model_dump(mode="json")
    sections = {section: {} for section in SECTIONS}
    sections["inventory"] = {"pipeline:configuration": config}
    sections["history"] = {
        "pipeline:declaration": {
            "actor_id": actor_id,
            "reason": data.reason,
            "expected_versions": data.expected_versions,
            "assurance": "user_or_ci_declared",
            "external_authenticity_verified": False,
        }
    }
    state = journal.snapshot(
        project_id=project_id,
        version="@pipeline",
        actor_id=actor_id,
        reason="Configure pipeline declarations",
        sections=sections,
        parents=[data.expected_policy] if data.expected_policy else [],
    )
    updates = [Update(ref=config_ref(project_id), expected=data.expected_policy, target=state)]
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=updates,
        branch_heads={project_id: data.expected_versions},
    )


def validate_source_role(configuration, part_id, source, role):
    if configuration is None:
        return
    config = PipelineConfiguration.model_validate(configuration)
    part = next((part for part in config.parts if part.part_id == part_id), None)
    if part is None:
        raise ValueError("Delivery part has no configured source authority")
    if role == "authority" and source == part.authority_source:
        return
    if role == "observation" and source in part.observation_sources:
        return
    raise ValueError("Source is not configured for the declared delivery-part role")


def resolve_context(
    journal, *, project_id, state, configuration, offset=0, limit=200, paginate=True
):
    if state not in reachable_states(journal, project_id):
        raise ValueError("Pipeline context requires committed product history")
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid pipeline context page")
    config = retained_config(journal, project_id, configuration)
    sections = load_sections(journal, state)
    resolved = resolve_sections(config, sections)
    rows = resolved["rows"]
    content = {
        "format": "dtvp.pipeline-context/1",
        "inventory_state": state,
        "configuration_state": configuration,
        "assurance": "user_or_ci_declared",
        "total": len(rows),
        "unmapped": sum(row["status"] == "unmapped" for row in rows),
        "unused_mapping_ids": resolved["unused_mapping_ids"],
    }
    return {
        **content,
        "digest": digest(canonical([content, rows])),
        "offset": offset,
        "limit": limit,
        "rows": rows[offset : offset + limit] if paginate else rows,
        "next_offset": offset + limit if paginate and offset + limit < len(rows) else None,
    }


def resolve_sections(configuration, sections):
    """Resolve unpublished immutable candidate sections without consulting refs."""
    config = PipelineConfiguration.model_validate(configuration).model_dump(mode="json")
    components = {
        value["bom-ref"]: value
        for key, value in sections["inventory"].items()
        if (key == "root" or key.startswith(("component:", "part-root:"))) and value.get("bom-ref")
    }
    contexts = [value for key, value in sections["ownership"].items() if key.startswith("context:")]
    if len(components) > 100000 or len(contexts) > 100000:
        raise ValueError("Pipeline context exceeds inventory bounds")
    models = {model["model_id"]: model for model in config["models"]}
    compiled = [
        (
            mapping,
            parse_team_mapping_key(mapping["component_selector"]),
            parse_team_mapping_key(mapping["context_selector"])
            if mapping["context_selector"]
            else None,
        )
        for mapping in config["mappings"]
    ]
    # Bound selector evaluations independently of output paging.
    if max(1, len(contexts) or len(components)) * len(compiled) > 2_000_000:
        raise ValueError("Pipeline mapping resolution exceeds evaluation bound")
    rows, used = [], set()
    result_bytes = 0
    targets = contexts or [
        {"component_ref": ref, "root_ref": None, "id": None} for ref in sorted(components)
    ]
    for context in targets:
        ref, root_ref = context["component_ref"], context.get("root_ref")
        component, root = components.get(ref), components.get(root_ref)
        if component is None:
            continue
        matched = []
        for mapping, selector, context_selector in compiled:
            if not selector_matches_identity(selector, component_identity(component)):
                continue
            if context_selector and (
                root is None
                or not selector_matches_identity(context_selector, component_identity(root))
            ):
                continue
            used.add(mapping["mapping_id"])
            matched.append(
                {
                    **mapping,
                    "model_revision": models[mapping["model_id"]]["revision"],
                    "model_sha256": models[mapping["model_id"]]["digest_sha256"],
                }
            )
        row = {
            "component_ref": ref,
            "context_id": context.get("id"),
            "root_ref": root_ref,
            "status": "mapped" if matched else "unmapped",
            "mappings": matched,
        }
        result_bytes += len(canonical(row))
        if result_bytes > 32 * 1024 * 1024:
            raise ValueError("Resolved pipeline context exceeds 32 MiB")
        rows.append(row)
    rows.sort(key=canonical)
    return {
        "rows": rows,
        "total": len(rows),
        "unmapped": sum(row["status"] == "unmapped" for row in rows),
        "unused_mapping_ids": sorted(
            mapping["mapping_id"]
            for mapping in config["mappings"]
            if mapping["mapping_id"] not in used
        ),
    }


def context_material(configuration, sections, context, *, components=None):
    """Only effective entity/model placements; unrelated rule edits are immaterial.

    Bulk callers should provide their request-local component index to avoid
    rebuilding it for every context. Component/entity names are not inferred IDs.
    """
    if components is None:
        components = {
            value["bom-ref"]: value
            for key, value in sections["inventory"].items()
            if (key == "root" or key.startswith(("component:", "part-root:")))
            and value.get("bom-ref")
        }
    component = components.get(context.get("component_ref"))
    root = components.get(context.get("root_ref"))
    if component is None:
        return []
    models = {model["model_id"]: model for model in configuration.get("models", [])}
    material = []
    for mapping in configuration.get("mappings", []):
        if not selector_matches_identity(
            parse_team_mapping_key(mapping["component_selector"]), component_identity(component)
        ):
            continue
        if mapping.get("context_selector") and (
            root is None
            or not selector_matches_identity(
                parse_team_mapping_key(mapping["context_selector"]), component_identity(root)
            )
        ):
            continue
        model = models[mapping["model_id"]]
        material.append(
            {
                "model_id": model["model_id"],
                "model_revision": model["revision"],
                "model_sha256": model["digest_sha256"],
                "entities": sorted(
                    [
                        entity
                        for entity in model["entities"]
                        if entity["entity_id"] in mapping["entity_ids"]
                    ],
                    key=canonical,
                ),
                "legacy_names": sorted(mapping.get("legacy_names", [])),
            }
        )
    return sorted({canonical(item): item for item in material}.values(), key=canonical)
