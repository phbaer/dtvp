"""Helpers for tests of the instance dump."""

import json
from pathlib import Path

from dtvp.bundle_io import ZipBundleWriter

FIXTURE_V1 = Path(__file__).resolve().parent / "fixtures" / "dump-v1"


def pack_tree(tree: Path, target: Path, *, manifest: dict | None = None) -> Path:
    """Pack a dump member tree into a ZIP: records and config in name order,
    the manifest last. ``manifest`` replaces the tree's manifest."""
    members = sorted(
        path
        for path in tree.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    )
    with open(target, "wb") as handle, ZipBundleWriter(handle) as bundle:
        for path in members:
            bundle.write_member(path.relative_to(tree).as_posix(), path.read_bytes())
        data = (
            (tree / "manifest.json").read_bytes()
            if manifest is None
            else (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        )
        bundle.write_member("manifest.json", data)
    return target


def fixture_manifest() -> dict:
    return json.loads((FIXTURE_V1 / "manifest.json").read_text(encoding="utf-8"))


def fixture_records(entity: str) -> list[dict]:
    path = FIXTURE_V1 / "records" / entity / f"{entity}-0001.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def build_dump(
    target: Path,
    *,
    records: dict[str, list[dict]] | None = None,
    change_manifest=None,
    config: dict[str, bytes | None] | None = None,
    raw_parts: dict[str, bytes] | None = None,
) -> Path:
    """A dump built from the frozen fixture with records, settings or the
    manifest changed; the manifest digests are recomputed unless
    ``change_manifest`` changes them afterwards. ``raw_parts`` gives the
    bytes of a record file instead of its records; it is counted by lines."""
    import hashlib

    from dtvp.backup import schemas
    from dtvp.bundle_io import jsonl_line

    manifest = fixture_manifest()
    members: dict[str, bytes] = {}
    for entity in schemas.ENTITY_ORDER:
        entity_records = (records or {}).get(entity, fixture_records(entity))
        spec = manifest["entities"][entity]
        if not entity_records:
            spec.update(records=0, parts=[])
            continue
        path = f"records/{entity}/{entity}-0001.jsonl"
        data = b"".join(jsonl_line(record) for record in entity_records)
        if path in (raw_parts or {}):
            data = raw_parts[path]
        count = data.count(b"\n")
        members[path] = data
        spec.update(
            records=count,
            parts=[
                {
                    "path": path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "records": count,
                }
            ],
        )
    settings = {
        name: (FIXTURE_V1 / spec["path"]).read_bytes() if not spec["absent"] else None
        for name, spec in manifest["config"].items()
    }
    settings.update(config or {})
    for name, data in settings.items():
        if data is None:
            manifest["config"][name] = {"absent": True}
        else:
            path = f"config/{name}.json"
            members[path] = data
            manifest["config"][name] = {
                "absent": False,
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
    if change_manifest is not None:
        manifest = change_manifest(manifest) or manifest
    with open(target, "wb") as handle, ZipBundleWriter(handle) as bundle:
        for name in sorted(members):
            bundle.write_member(name, members[name])
        bundle.write_member(
            "manifest.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        )
    return target
