"""Explicit occurrence relationships across pinned delivery parts; never identity merges."""

from typing import Literal

from pydantic import Field, field_validator

from dtvp.knowledge.journal import Name, Sha
from dtvp.schemas import RequestModel


class PartOccurrence(RequestModel):
    part_id: Name
    state: Sha
    ref: str = Field(min_length=1, max_length=3000)


class CrossPartRelationship(RequestModel):
    relationship_id: Name
    kind: Literal["DEPENDS_ON", "CONTAINS"]
    from_: PartOccurrence = Field(alias="from")
    to: PartOccurrence
    rationale: str = Field(min_length=1, max_length=2000)

    @field_validator("rationale")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("An explicit cross-part relationship requires a rationale")
        return value


def qualify_relationships(declarations, selected, namespaced_ref):
    """Both endpoints must exist in the exact selected immutable occurrence sets."""
    output, ids, edges = [], set(), set()
    for declared in declarations:
        if declared.relationship_id in ids:
            raise ValueError("Cross-part relationship IDs must be distinct")
        ids.add(declared.relationship_id)
        if declared.from_.part_id == declared.to.part_id:
            raise ValueError("Cross-part relationships must address different delivery parts")
        endpoints = []
        for endpoint in (declared.from_, declared.to):
            chosen = selected.get(endpoint.part_id)
            if (
                not chosen
                or endpoint.state != chosen["state"]
                or endpoint.ref not in chosen["refs"]
            ):
                raise ValueError(
                    "Cross-part endpoint is absent from its exact selected part revision"
                )
            endpoints.append(namespaced_ref(endpoint.part_id, endpoint.ref))
        identity = declared.kind, *endpoints
        if identity in edges:
            raise ValueError("Duplicate cross-part occurrence relationships are not permitted")
        edges.add(identity)
        output.append(
            {
                "from": endpoints[0],
                "to": endpoints[1],
                "kind": declared.kind,
                "origin": "dtvp.assembly-explicit/1",
                "relationship_id": declared.relationship_id,
                "from_origin": declared.from_.model_dump(mode="json"),
                "to_origin": declared.to.model_dump(mode="json"),
                "rationale": declared.rationale,
            }
        )
    return output
