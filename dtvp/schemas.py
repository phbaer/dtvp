from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class WorkspaceInput(RequestModel):
    name: str = Field(min_length=1, max_length=200)


class MemberInput(RequestModel):
    issuer: str = Field(min_length=1, max_length=500)
    subject: str = Field(min_length=1, max_length=500)
    name: str = Field(min_length=1, max_length=200)
    roles: list[
        Literal[
            "viewer",
            "analyst",
            "reviewer",
            "coordinator",
            "license_analyst",
            "license_reviewer",
            "documentary_analyst",
            "documentary_reviewer",
            "admin",
        ]
    ] = Field(max_length=9)


class ProjectInput(RequestModel):
    workspace_id: str
    name: str = Field(min_length=1, max_length=200)




class ShareInput(RequestModel):
    workspace_id: str
    capabilities: list[
        Literal[
            "read",
            "write",
            "assess",
            "approve",
            "snapshot",
            "evidence",
            "rescore",
            "license_assess",
            "license_approve",
            "documentary_assess",
            "documentary_approve",
        ]
    ]


class TokenInput(RequestModel):
    workspace_id: str
    name: str = Field(min_length=1, max_length=200)
    projects: list[str] = Field(default_factory=list, max_length=100)
    capabilities: list[
        Literal[
            "read",
            "write",
            "assess",
            "approve",
            "snapshot",
            "evidence",
            "export",
            "rescore",
            "license_assess",
            "license_approve",
            "documentary_assess",
            "documentary_approve",
        ]
    ]
    hours: int = Field(default=24, ge=1, le=24 * 90)

Justification = Literal[
    "code_not_present", "code_not_reachable", "requires_configuration",
    "requires_dependency", "requires_environment", "protected_by_compiler",
    "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control", "other",
] | None
