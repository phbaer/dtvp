from __future__ import annotations

from typing import Any, Callable

from ..rescore_rule_services import (
    build_rescore_rule_sync_payloads,
    build_rescore_rule_sync_preview,
)
from .base import BulkWorkflowContext, BulkWorkflowPlugin


def create_rescore_rule_sync_workflow(
    load_rules: Callable[[], dict[str, Any]],
) -> BulkWorkflowPlugin:
    return BulkWorkflowPlugin(
        id="rescore-rule-sync",
        label="Sync CVSS Rules",
        description="Repair stored CVSS vectors that no longer follow configured rules.",
        preview_builder=lambda context: build_rescore_rule_sync_preview(
            context.groups, load_rules()
        ),
        payload_builder=lambda context, ids: build_rescore_rule_sync_payloads(
            context.groups, load_rules(), ids
        ),
        selection_predicate=lambda item: int(item.get("syncable_finding_count") or 0) > 0,
    )
