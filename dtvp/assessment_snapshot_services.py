from typing import Any, Iterable


ASSESSMENT_INSTANCE_KEY_FIELDS = (
    "project_uuid",
    "component_uuid",
    "vulnerability_uuid",
)


def assessment_identity_key(
    source: dict[str, Any],
) -> tuple[str, str, str] | None:
    values = tuple(
        str(source.get(key) or "") for key in ASSESSMENT_INSTANCE_KEY_FIELDS
    )
    return values if all(values) else None


def build_assessment_group_index(
    groups: list[dict[str, Any]],
) -> dict[str, Any]:
    positions: dict[str, int] = {}
    by_finding_uuid: dict[str, set[str]] = {}
    by_identity: dict[tuple[str, str, str], set[str]] = {}

    for position, group in enumerate(groups):
        group_id = str(group.get("id") or "")
        if not group_id:
            continue
        positions[group_id] = position
        for affected_version in group.get("affected_versions") or []:
            for component in affected_version.get("components") or []:
                finding_uuid = str(component.get("finding_uuid") or "")
                if finding_uuid:
                    by_finding_uuid.setdefault(finding_uuid, set()).add(group_id)
                identity = assessment_identity_key(component)
                if identity is not None:
                    by_identity.setdefault(identity, set()).add(group_id)

    return {
        "source": groups,
        "size": len(groups),
        "positions": positions,
        "by_finding_uuid": by_finding_uuid,
        "by_identity": by_identity,
    }


def assessment_group_index_matches(
    index: Any,
    groups: list[dict[str, Any]],
) -> bool:
    return (
        isinstance(index, dict)
        and index.get("source") is groups
        and index.get("size") == len(groups)
        and isinstance(index.get("positions"), dict)
        and isinstance(index.get("by_finding_uuid"), dict)
        and isinstance(index.get("by_identity"), dict)
    )


def find_assessment_group_ids(
    index: dict[str, Any],
    finding_uuids: Iterable[str],
    identities: Iterable[tuple[str, str, str]],
) -> set[str]:
    group_ids: set[str] = set()
    by_finding_uuid = index["by_finding_uuid"]
    by_identity = index["by_identity"]
    for finding_uuid in finding_uuids:
        group_ids.update(by_finding_uuid.get(finding_uuid, ()))
    for identity in identities:
        group_ids.update(by_identity.get(identity, ()))
    return group_ids
