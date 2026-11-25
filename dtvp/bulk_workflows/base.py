from __future__ import annotations

import hashlib
import json
import dataclasses
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


PreviewBuilder = Callable[["BulkWorkflowContext"], dict[str, Any]]
PayloadBuilder = Callable[
    ["BulkWorkflowContext", list[str]],
    tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, int]],
]
DocumentBuilder = Callable[["BulkWorkflowContext", list[str]], str]
SelectionPredicate = Callable[[dict[str, Any]], bool]


# Apply summary key: payloads left out because their finding changed after
# the preview (see ``BulkWorkflowContext.stored_assessments``).
CHANGED_SINCE_PREVIEW = "changed_since_preview"


@dataclass(frozen=True)
class BulkWorkflowContext:
    task_id: str
    groups: list[dict[str, Any]]
    user: str
    team_mapping: dict[str, Any] = field(default_factory=dict)
    rescore_rules: dict[str, Any] = field(default_factory=dict)
    result_store: Any = None
    assessment_records: Optional[list[dict[str, Any]]] = None
    assessment_diagnostics: dict[str, int] = field(default_factory=dict)
    # The earlier versions of the assessments that ever named a ticket, per
    # finding (project, component, vulnerability), oldest first.
    ticket_histories: Optional[Callable[[], dict[tuple[str, str, str], list[dict[str, Any]]]]] = None
    # Groups whose new findings (added by a new project version) the
    # reviewer chose to include; nothing is copied onto them otherwise.
    include_new_findings: frozenset[str] = frozenset()
    # The uploaded input of a workflow that reads one (``source_kind``).
    source: Any = None
    # The stored assessment of each given finding (state, details,
    # suppressed, revision), read when the payloads are built. A payload
    # may carry ``expected_revision``; it is written only if the finding
    # still has that revision, else it is skipped as changed since preview.
    stored_assessments: Optional[Callable[[list[dict[str, Any]]], list[dict[str, Any]]]] = None
    # Per project version, the assessed gone findings whose component River
    # never knew and the reported findings of the same vulnerability
    # (``CacheManager.unknown_component_records``).
    unknown_component_records: Optional[Callable[[str], dict[str, dict[str, Any]]]] = None


def _same_text(left: Any, right: Any) -> bool:
    return "".join(str(left or "").split()) == "".join(str(right or "").split())


def guard_against_later_saves(
    context: BulkWorkflowContext,
    payloads: list[tuple[dict[str, Any], dict[str, Any]]],
    skipped: dict[str, int],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Leave out payloads whose finding was saved since the workflow read it.

    Each ``(instance, payload)`` was built from ``instance``, the finding as
    the workflow read it. A finding whose stored state, text or suppression
    differs now would lose that save, so it is left out and counted as
    ``changed_since_preview``. The others carry the revision they are based
    on; the write checks it again, for a save in between. A payload that
    already carries ``expected_revision`` is left as it is.
    """
    read = context.stored_assessments
    unchecked = [
        index for index, (_instance, payload) in enumerate(payloads)
        if "expected_revision" not in payload
    ]
    if not callable(read) or not unchecked:
        return payloads
    stored = read([payloads[index][0] for index in unchecked])
    current_of = dict(zip(unchecked, stored))
    kept = []
    for index, (instance, payload) in enumerate(payloads):
        current = current_of.get(index)
        if current is None:
            kept.append((instance, payload))
            continue
        if current.get("recorded") is False:
            # No record yet: nothing local to compare with. The write still
            # refuses if a save creates one in the meantime.
            kept.append((instance, {**payload, "expected_revision": 0}))
            continue
        state = instance.get("analysis_state") or instance.get("analysisState") or "NOT_SET"
        details = instance.get("analysis_details")
        if details is None:
            details = instance.get("analysisDetails")
        if (
            str(current.get("state") or "NOT_SET") != str(state)
            or bool(current.get("suppressed")) != bool(instance.get("is_suppressed", False))
            or not _same_text(current.get("details"), details)
        ):
            skipped[CHANGED_SINCE_PREVIEW] = skipped.get(CHANGED_SINCE_PREVIEW, 0) + 1
            continue
        kept.append((instance, {**payload, "expected_revision": int(current.get("revision") or 0)}))
    return kept


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
    # The kind of uploaded input the workflow reads; ``None`` for none.
    source_kind: Optional[str] = None

    def metadata(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "supports_apply": self.payload_builder is not None,
            "supports_document": self.document_builder is not None,
            "requires_source": self.source_kind is not None,
            "source_kind": self.source_kind,
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
        payloads, skipped = self.payload_builder(context, group_ids)
        # Every workflow writes texts built from what it read: none may
        # replace a save made since.
        return guard_against_later_saves(context, payloads, skipped), skipped

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


def preview_as_shown(context: BulkWorkflowContext) -> BulkWorkflowContext:
    """The context a preview is shown with: without the new findings the
    reviewer includes at apply. Including them changes a group's repair
    payloads (finding_count, repairs, requires_review), and the preview the
    reviewer saw did not include them: an apply compares against the preview
    as shown, and writes with the includes."""
    if not context.include_new_findings:
        return context
    return dataclasses.replace(context, include_new_findings=frozenset())


def build_preview_token(
    plugin: BulkWorkflowPlugin,
    *,
    task_id: str,
    filter_payload: dict[str, Any],
) -> str:
    """What a preview is bound to: the workflow and its version, the task,
    the filters and the uploaded file (``source_sha256``). Not the content:
    the background sync writes all the time, so the content is checked per
    selected group (``group_fingerprints``)."""
    canonical = json.dumps(
        {
            "workflow": plugin.id,
            "version": plugin.version,
            "task_id": task_id,
            "filters": filter_payload,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _record_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def canonical_item(value: Any) -> Any:
    """A preview item as the decision sees it: mappings by key, and lists
    in a canonical order. A list's order (the instances, the places, the
    repairs) is how a read happened to return them, not what the decision
    depends on; the workflow's payloads come from a fresh preview anyway."""
    if isinstance(value, dict):
        return {str(key): canonical_item(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return sorted((canonical_item(child) for child in value), key=_record_key)
    return value


def group_fingerprints(preview: dict[str, Any]) -> dict[str, str]:
    """Per group, a fingerprint of its preview item (``canonical_item``):
    what an apply checks for each group it selects."""
    fingerprints: dict[str, str] = {}
    for item in preview.get("items") or []:
        group_id = str(item.get("group_id") or item.get("id") or "").strip()
        if not group_id:
            continue
        fingerprints[group_id] = hashlib.sha256(
            _record_key(canonical_item(item)).encode("utf-8")
        ).hexdigest()
    return fingerprints


def diff_items(before: Any, after: Any, *, limit: int = 20) -> list[dict[str, Any]]:
    """Where two preview items differ, field by field: ``path`` (dots for
    keys, ``[]`` for a list whose contents differ), and the values before and
    after, shortened. For a refused apply, so a reviewer can see what changed."""
    changes: list[dict[str, Any]] = []

    def short(value: Any) -> Any:
        text = _record_key(value)
        return text if len(text) <= 200 else text[:197] + "..."

    def walk(path: str, old: Any, new: Any) -> None:
        if len(changes) >= limit or old == new:
            return
        if isinstance(old, dict) and isinstance(new, dict):
            for key in sorted(set(old) | set(new), key=str):
                walk(f"{path}.{key}" if path else str(key), old.get(key), new.get(key))
            return
        if isinstance(old, list) and isinstance(new, list):
            # The canonical order: a reordering is not a change.
            if canonical_item(old) != canonical_item(new):
                changes.append({"path": f"{path}[]", "before": short(old), "after": short(new)})
            return
        changes.append({"path": path or "(item)", "before": short(old), "after": short(new)})

    walk("", canonical_item(before), canonical_item(after))
    return changes
