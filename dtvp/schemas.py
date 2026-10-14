from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class WorkspaceInput(RequestModel):
    name: str = Field(min_length=1, max_length=200)


class MemberInput(RequestModel):
    issuer: str = Field(min_length=1, max_length=500)
    subject: str = Field(min_length=1, max_length=500)
    name: str = Field(min_length=1, max_length=200)
    roles: list[Literal["viewer", "analyst", "reviewer", "admin"]] = Field(max_length=4)


class ProjectInput(RequestModel):
    workspace_id: str
    name: str = Field(min_length=1, max_length=200)


class ReleaseInput(RequestModel):
    version: str = Field(min_length=1, max_length=200)


class ShareInput(RequestModel):
    workspace_id: str
    capabilities: list[Literal["read", "write", "assess", "approve", "snapshot", "evidence"]]


class TokenInput(RequestModel):
    workspace_id: str
    name: str = Field(min_length=1, max_length=200)
    projects: list[str] = Field(default_factory=list, max_length=100)
    capabilities: list[
        Literal["read", "write", "assess", "approve", "snapshot", "evidence", "export"]
    ]
    hours: int = Field(default=24, ge=1, le=24 * 90)


class ImportInput(RequestModel):
    schema_version: Literal["dtvp.ingestion/1"] = "dtvp.ingestion/1"
    source: str = Field(min_length=1, max_length=200)
    event_id: str = Field(min_length=1, max_length=200)
    occurred_at: datetime
    completeness: Literal["complete", "partial"] = "complete"
    context: dict = Field(default_factory=dict)
    sbom: dict


class RescoreInput(RequestModel):
    kind: Literal["manual", "rule", "evidence"]
    base_vector: str = Field(default="", max_length=1024)
    vector: str = Field(default="", max_length=1024)
    evidence_id: str | None = None
    policy_digest: str = Field(default="", max_length=64)
    preview_digest: str = Field(default="", max_length=64)
    rule_basis: Literal["applicability", "false_positive"] = "applicability"
    rationale: str = Field(min_length=1, max_length=6000)


class DecisionInput(RequestModel):
    expected_version: int = Field(ge=1)
    state: Literal["affected", "not_affected", "fixed", "under_investigation"]
    rationale: str = Field(min_length=1, max_length=6000)
    details: dict = Field(default_factory=dict)
    rescoring: RescoreInput | None = None


class ApprovalInput(RequestModel):
    expected_version: int = Field(ge=1)
    decision_id: str
    action: Literal["approve", "request_changes"] = "approve"


class MetadataInput(RequestModel):
    expected_version: int = Field(ge=0)
    metadata: dict


class EvidenceInput(RequestModel):
    schema_version: Literal["dtvp.evidence/1"] = "dtvp.evidence/1"
    source: str = Field(min_length=1, max_length=200)
    external_id: str = Field(min_length=1, max_length=200)
    snapshot_id: str | None = None
    assertion: dict


class SnapshotInput(RequestModel):
    release_id: str
    revision_id: str | None = None


class JobInput(RequestModel):
    kind: Literal["match", "enrich", "import-dt"]
    release_id: str
    provider: Literal["osv", "nvd", "circl", "demo", "demo-failure"] | None = None
    external_project_id: str | None = None


class BulkItem(RequestModel):
    finding_id: str
    expected_version: int = Field(ge=1)
    decision_id: str


class BulkInput(RequestModel):
    items: list[BulkItem] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def distinct_findings(self):
        if len({item.finding_id for item in self.items}) != len(self.items):
            raise ValueError("Each finding may appear only once in a selection")
        return self


class BulkApply(BulkInput):
    preview_digest: str
