from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


PreviewBuilder = Callable[["BulkWorkflowContext"], dict[str, Any]]
PayloadBuilder = Callable[
    ["BulkWorkflowContext", list[str]],
    tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]],
]
DocumentBuilder = Callable[["BulkWorkflowContext", list[str]], str]
SelectionPredicate = Callable[[dict[str, Any]], bool]


@dataclass(frozen=True)
class BulkWorkflowContext:
    task_id: str
    groups: list[dict[str, Any]]
    user: str
    team_mapping: dict[str, Any] = field(default_factory=dict)
    result_store: Any = None
    assessment_records: Optional[list[dict[str, Any]]] = None
    assessment_diagnostics: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class BulkWorkflowPlugin:
    id: str
    label: str
    description: str
    preview_builder: PreviewBuilder
    payload_builder: Optional[PayloadBuilder] = None
    document_builder: Optional[DocumentBuilder] = None
    selection_predicate: SelectionPredicate = lambda _item: True
    version: int = 1

    def metadata(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "supports_apply": self.payload_builder is not None,
            "supports_document": self.document_builder is not None,
            "version": self.version,
        }

    def preview(self, context: BulkWorkflowContext) -> dict[str, Any]:
        return self.preview_builder(context)

    def build_payloads(
        self,
        context: BulkWorkflowContext,
        group_ids: list[str],
    ) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]]:
        if self.payload_builder is None:
            raise ValueError(f"Bulk workflow {self.id} does not support apply")
        return self.payload_builder(context, group_ids)

    def build_document(
        self,
        context: BulkWorkflowContext,
        group_ids: list[str],
    ) -> str:
        if self.document_builder is None:
            raise ValueError(f"Bulk workflow {self.id} does not support documents")
        return self.document_builder(context, group_ids)

    def selectable_ids(self, preview: dict[str, Any]) -> list[str]:
        return preview_candidate_ids(preview, predicate=self.selection_predicate)


class BulkWorkflowRegistry:
    def __init__(self, plugins: list[BulkWorkflowPlugin] | None = None):
        self._plugins: dict[str, BulkWorkflowPlugin] = {}
        for plugin in plugins or []:
            self.register(plugin)

    def register(self, plugin: BulkWorkflowPlugin) -> None:
        if not plugin.id or plugin.id in self._plugins:
            raise ValueError(f"Duplicate or empty bulk workflow id: {plugin.id}")
        self._plugins[plugin.id] = plugin

    def get(self, workflow_id: str) -> BulkWorkflowPlugin | None:
        return self._plugins.get(str(workflow_id or "").strip())

    def all(self) -> list[BulkWorkflowPlugin]:
        return list(self._plugins.values())


def preview_candidate_ids(
    preview: dict[str, Any],
    *,
    predicate: SelectionPredicate = lambda _item: True,
) -> list[str]:
    return sorted(
        {
            str(item.get("group_id") or item.get("id") or "").strip()
            for item in (preview.get("items") or [])
            if predicate(item)
            and str(item.get("group_id") or item.get("id") or "").strip()
        }
    )


def build_preview_token(
    plugin: BulkWorkflowPlugin,
    *,
    task_id: str,
    filter_payload: dict[str, Any],
    preview: dict[str, Any],
) -> str:
    canonical_items = sorted(
        (preview.get("items") or []),
        key=lambda item: str(item.get("group_id") or item.get("id") or ""),
    )
    canonical = json.dumps(
        {
            "workflow": plugin.id,
            "version": plugin.version,
            "task_id": task_id,
            "filters": filter_payload,
            "candidate_ids": plugin.selectable_ids(preview),
            "items": canonical_items,
            "summary": preview.get("summary") or {},
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
