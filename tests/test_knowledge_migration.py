"""Local cutover rehearsal preserves history without granting native authority."""

import json
from copy import deepcopy

import pytest

from dtvp.knowledge.journal import Conflict, Journal, Ref
from dtvp.knowledge.migration import (
    MigrationApply,
    MigrationInput,
    apply_migration,
    preview_migration,
)
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.fixture
def migration(tmp_path):
    journal = Journal(tmp_path / "journal")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"bom-ref": "library", "name": "Library", "version": "1", "type": "library"}
        ],
        "dependencies": [{"ref": "library", "dependsOn": []}],
    }
    original = json.dumps(sbom, indent=2).encode() + b"\n"
    source_sha = digest(original)
    payload = {
        "schema_version": "dtvp.snapshot/1",
        "project": {"id": "legacy", "metadata": {"owner": "Old labels"}},
        "release": {"id": "release", "version": "legacy-1"},
        "coverage": {"inventory": "complete"},
        "sbom": sbom,
        "original_sha256": source_sha,
        "source_revisions": [{"id": "revision", "sha256": source_sha, "source": "old-pipeline"}],
        "components": [
            {
                "id": "component",
                "refs": ["library"],
                "metadata": {"license_note": "Historical note", "owner": "Old team"},
            }
        ],
        "findings": [
            {
                "id": "finding",
                "identifier": "CVE-2099-1234",
                "component_id": "component",
                "active": True,
                "description": "Captured source advisory",
                "observations": [
                    {
                        "id": "observation",
                        "source": "old-pipeline",
                        "advisory": {
                            "id": "CVE-2099-1234",
                            "description": "Source description",
                            "ratings": [{"vector": BASE, "score": 9.8}],
                        },
                    }
                ],
                "decisions": [
                    {
                        "id": "decision",
                        "state": "not_affected",
                        "rationale": "Old reasoning",
                        "author_id": "old-author",
                    }
                ],
                "approval": {"id": "approval", "reviewer_id": "old-reviewer"},
                "adopted_rescoring": {"score": 0, "vector": BASE + "/CR:L"},
            }
        ],
    }
    return journal, payload, {source_sha: original}


def arguments(migration):
    journal, payload, artifacts = migration
    raw = canonical(payload)
    data = MigrationInput(
        request_id="migrate",
        snapshot_id="snapshot",
        snapshot_sha=digest(raw),
        expected=None,
        expected_policy=None,
        expected_evidence=None,
        source="future-ci",
        build_number=0,
        occurred_at="2026-10-16T01:00:00Z",
        acknowledge_historical_claims=True,
    )
    return dict(
        project_id="product",
        version="1",
        actor_id="administrator",
        data=data,
        bundle=raw,
        source_artifacts=artifacts,
        source_proof={
            "snapshot_id": "snapshot",
            "snapshot_sha": digest(raw),
            "kind": "local_snapshot_membership",
        },
    )


def apply(journal, args):
    preview = preview_migration(journal, **args)
    return apply_migration(
        journal,
        **{
            **args,
            "data": MigrationApply(
                **args["data"].model_dump(), preview_digest=preview["preview_digest"]
            ),
        },
    )


def test_pure_preview_exact_artifact_retention_and_no_human_authority(migration):
    journal, payload, originals = migration
    args = arguments(migration)
    before = journal.head(), journal.references(), set(journal.objects.root.glob("*/*"))
    preview = preview_migration(journal, **args)
    assert preview == preview_migration(journal, **args)
    assert (journal.head(), journal.references(), set(journal.objects.root.glob("*/*"))) == before
    assert preview["statistics"]["captured_latest_approvals"] == 1
    assert preview["statistics"]["mapped_source_targets"] == 1
    receipt = apply(journal, args)
    state = receipt[1].updates[0].target
    sections = load_sections(journal, state)
    assert all(not sections[key] for key in ("assessments", "reviews", "scoring"))
    assert sections["inventory"]["baseline"]["source"] == "future-ci"
    assert sections["inventory"]["baseline"]["collection"]["package_coverage"] == "unknown"
    claim = next(
        value for key, value in sections["history"].items() if key.startswith("legacy-finding:")
    )
    assert claim["claim"] == payload["findings"][0] and not claim["native_approval"]
    observation = next(iter(sections["vulnerabilities"].values()))
    assert observation["advisory"]["ratings"] == [{"vector": BASE, "score": 9.8}]
    assert "adopted_rescoring" not in observation
    assert journal.objects.read(args["data"].snapshot_sha) == args["bundle"]
    for sha, raw in originals.items():
        assert sha in journal.state(state).artifacts and journal.objects.read(sha) == raw
    assert any("older approvals" in value for value in preview["limitations"])


def test_missing_base_keeps_unknown_queue_claim_and_archives_unmapped_and_inactive(migration):
    journal, payload, _ = migration
    payload["findings"][0]["observations"][0]["advisory"]["ratings"] = [
        {"vector": BASE + "/CR:L", "score": 0},
        {"vector": 42},
    ]
    for identity, changes in [
        ("absent", {"component_id": "missing"}),
        ("inactive", {"active": False}),
    ]:
        payload["findings"].append({**deepcopy(payload["findings"][0]), "id": identity, **changes})
    args = arguments(migration)
    preview = preview_migration(journal, **args)
    assert preview["statistics"]["captured_findings"] == 3
    assert preview["unresolved_total"] == 3
    state = apply(journal, args)[1].updates[0].target
    sections = load_sections(journal, state)
    assert len(sections["vulnerabilities"]) == 1
    assert next(iter(sections["vulnerabilities"].values()))["advisory"]["ratings"] == []
    assert len([key for key in sections["history"] if key.startswith("legacy-finding:")]) == 3
    assert not sections["ownership"].get("rules")


def test_exact_retry_before_changed_heads_and_no_overwrite(migration):
    journal, _, _ = migration
    args = arguments(migration)
    preview = preview_migration(journal, **args)
    data = MigrationApply(**args["data"].model_dump(), preview_digest=preview["preview_digest"])
    applied = {**args, "data": data}
    first = apply_migration(journal, **applied)
    state = first[1].updates[0].target
    newer = import_inventory(
        journal,
        project_id="product",
        version="1",
        actor_id="producer",
        request_id="next-build",
        expected=state,
        source="future-ci",
        build_number=1,
        occurred_at="2026-10-17T01:00:00Z",
        sbom=args and migration[1]["sbom"],
    )
    assert (
        apply_migration(
            journal, **{**applied, "bundle": b"unavailable now", "source_artifacts": {}}
        )
        == first
    )
    assert journal.resolve(Ref(project_id="product", name="1")) == newer[1].updates[0].target
    with pytest.raises(Conflict):
        apply_migration(journal, **{**applied, "data": data.model_copy(update={"source": "other"})})
    with pytest.raises(Conflict, match="empty native branch"):
        preview_migration(
            journal, **{**args, "data": args["data"].model_copy(update={"request_id": "another"})}
        )


def test_corrupt_inputs_changed_digest_and_policy_publication_race_do_not_advance(
    migration, monkeypatch
):
    from dtvp.knowledge.journal import SECTIONS, Update
    from dtvp.knowledge.ownership import policy_ref

    journal, _, _ = migration
    args = arguments(migration)
    with pytest.raises(ValueError, match="digest"):
        preview_migration(journal, **{**args, "bundle": b"wrong"})
    with pytest.raises(ValueError, match="exact original"):
        preview_migration(journal, **{**args, "source_artifacts": {}})
    preview = preview_migration(journal, **args)
    data = MigrationApply(**args["data"].model_dump(), preview_digest=preview["preview_digest"])
    with pytest.raises(Conflict, match="preview"):
        apply_migration(
            journal, **{**args, "data": data.model_copy(update={"preview_digest": "f" * 64})}
        )
    original_publish = journal.publish

    def race(**kwargs):
        policy = journal.snapshot(
            project_id="product",
            version="@ownership",
            actor_id="administrator",
            reason="Concurrent policy",
            sections={name: {} for name in SECTIONS},
        )
        original_publish(
            request_id="policy-change",
            fingerprint="e" * 64,
            updates=[Update(ref=policy_ref("product"), expected=None, target=policy)],
        )
        return original_publish(**kwargs)

    monkeypatch.setattr(journal, "publish", race)
    with pytest.raises(Conflict):
        apply_migration(journal, **{**args, "data": data})
    assert journal.resolve(Ref(project_id="product", name="1")) is None


def test_embedded_sbom_ratings_are_historical_filtered_and_inactive_claims_archived(migration):
    journal, payload, _ = migration
    payload["sbom"]["vulnerabilities"] = [
        {
            "id": "CVE-2099-1234",
            "affects": [{"ref": "library"}],
            "ratings": [{"vector": BASE + "/CR:L/IR:L/AR:L", "score": 1.0}],
        },
        {
            "id": "CVE-2099-9999",
            "affects": [{"ref": "library"}],
            "ratings": [{"vector": BASE, "score": 0}],
        },
        {
            "id": "CVE-2099-7777",
            "affects": [{"ref": "library"}],
            "ratings": [{"vector": BASE, "score": 9.8}],
        },
    ]
    payload["findings"].append(
        {
            **deepcopy(payload["findings"][0]),
            "id": "inactive",
            "identifier": "CVE-2099-7777",
            "active": False,
        }
    )
    originals = migration[2]
    original = canonical(payload["sbom"])
    originals.clear()
    originals[digest(original)] = original
    payload["original_sha256"] = digest(original)
    payload["source_revisions"][0]["sha256"] = digest(original)
    args = arguments(migration)
    preview = preview_migration(journal, **args)
    sections = load_sections(journal, apply(journal, args)[1].updates[0].target)
    observations = list(sections["vulnerabilities"].values())
    assert len(observations) == preview["statistics"]["native_source_observations"] == 3
    assert all(
        value["source"] == "legacy-v2-snapshot"
        and value["legacy_snapshot"]["trust"] == "historical_unverified"
        for value in observations
    )
    assert {value["identifier"] for value in observations} == {"CVE-2099-1234", "CVE-2099-9999"}
    embedded = [
        value
        for value in observations
        if value["legacy_snapshot"].get("channel") == "selected-original"
    ]
    assert len(embedded) == 2 and all(not value["advisory"]["ratings"] for value in embedded)
    assert preview["statistics"]["original_inactive_archived"] == 1
    assert len([key for key in sections["history"] if key.startswith("legacy-embedded:")]) == 3


@pytest.mark.parametrize(
    "form,expected",
    [
        ("json", "7d5133ec01693f5cd0e9427e6c4c63f38318bae9136e917673ad7c93936cc4cd"),
        ("raw", "cd2439287c2293f90d9a562bb9e4d7edd26b1cb02def1bf71932ffa0e127e98f"),
    ],
)
def test_intake_preserves_pre_extraction_operation_fingerprints(tmp_path, form, expected):
    """Golden values captured from committed service before pure helper extraction."""
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"bom-ref": "library", "name": "Library", "version": "1", "type": "library"}
        ],
    }
    args = {"sbom": bom} if form == "json" else {"raw": canonical(bom)}
    journal = Journal(tmp_path / "journal")
    receipt = import_inventory(
        journal,
        project_id="product",
        version="1",
        actor_id="producer",
        request_id="compatibility",
        expected=None,
        source="ci",
        build_number=1,
        occurred_at="2026-10-16T01:00:00Z",
        **args,
    )
    assert receipt[1].fingerprint == expected


@pytest.mark.parametrize(
    "text",
    [
        "--- [Team: Alpha] [State: not_affected] [Assessed By: Alice] [Reviewed By: Bob] ---\nDeployment excludes this path.",
        "Reviewed deployment excludes this path. No structured metadata.",
    ],
)
def test_dt_documentation_survives_unknown_base_without_becoming_native_approval(migration, text):

    from dtvp.knowledge.legacy import legacy_claims

    journal, payload, _ = migration
    advisory = payload["findings"][0]["observations"][0]["advisory"]
    advisory["ratings"] = []
    advisory["properties"] = [
        {
            "name": "dtvp:dt-analysis",
            "value": json.dumps({"analysisState": "NOT_AFFECTED", "analysisDetails": text}),
        }
    ]
    sections = load_sections(journal, apply(journal, arguments(migration))[1].updates[0].target)
    claims = legacy_claims(list(sections["vulnerabilities"].values()))
    assert claims and claims[0]["raw_text"] == text
    assert not claims[0]["approved"] and not claims[0]["authenticated_identity"]
    assert not sections["assessments"] and not sections["reviews"] and not sections["scoring"]


def test_selected_original_mapping_drift_is_explicit_without_name_matching(migration):
    journal, payload, _ = migration
    payload["sbom"]["components"][0]["bom-ref"] = "old-normalized-ref"
    payload["sbom"]["dependencies"] = [{"ref": "old-normalized-ref", "dependsOn": []}]
    payload["components"][0]["refs"] = ["old-normalized-ref"]
    args = arguments(migration)
    preview = preview_migration(journal, **args)
    assert preview["statistics"]["mapped_source_targets"] == 0
    assert preview["component_mappings"][0]["unresolved_refs"] == ["old-normalized-ref"]
    assert preview["unresolved"][0]["reasons"] == ["explicit_component_ref_unavailable"]
    sections = load_sections(journal, apply(journal, args)[1].updates[0].target)
    assert any(
        component.get("bom-ref") == "library" for component in sections["inventory"].values()
    )
    assert not sections["vulnerabilities"]


def test_unsupported_selected_original_cannot_fall_back_to_legacy_normalized_bom(migration):
    journal, payload, originals = migration
    raw = b'{"unsupportedLegacyFormat":true}'
    originals.clear()
    originals[digest(raw)] = raw
    payload["original_sha256"] = digest(raw)
    payload["source_revisions"][0]["sha256"] = digest(raw)
    before = journal.head(), journal.references()
    with pytest.raises(ValueError):
        preview_migration(journal, **arguments(migration))
    assert (journal.head(), journal.references()) == before
