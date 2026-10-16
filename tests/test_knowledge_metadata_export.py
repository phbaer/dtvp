"""Issued consumers receive exact, server-derived annotation applicability."""

import copy
from datetime import date

import pytest

import dtvp.knowledge.exports as exports
from dtvp.knowledge.issued_exports import issue_export
from dtvp.knowledge.journal import Journal, Ref, Update
from dtvp.knowledge.metadata import identity_fingerprint, metadata_key
from dtvp.storage import canonical, digest
from tests.test_knowledge_assessments import current, head, seed
from tests.test_knowledge_metadata import data, read, save


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def publish(journal, parent, sections, version="7.1.1", artifacts=()):
    state = journal.snapshot(
        project_id="project",
        version=version,
        actor_id="fixture",
        reason="Metadata fixture",
        sections=sections,
        parents=[parent],
        artifacts=artifacts,
    )
    ref = Ref(project_id="project", name=version)
    journal.publish(
        request_id="publish-" + state,
        fingerprint=digest(state.encode()),
        updates=[Update(ref=ref, expected=journal.resolve(ref), target=state)],
    )
    return state


def test_register_preserves_authorship_and_distinguishes_current_stale_absent_and_version(journal):
    seed(journal)
    assert "component_metadata" not in exports.build_bundle(journal, head(journal))
    save(journal, data(journal))
    original = head(journal)
    record = read(journal)
    before = exports.build_bundle(journal, original)
    register = before["component_metadata"]
    assert register["items"] == [record] and register["by_status"] == {"current": 1}
    assert (
        register["items"][0]["payload"]["annotations"]["support"]["support_until"] == "2028-12-31"
    )
    assert register["items"][0]["payload"]["actor_id"] == "manager"
    assert "approved" not in register["items"][0]
    sections = copy.deepcopy(current(journal))
    sections["inventory"]["component:lib"]["version"] = "changed"
    stale = publish(journal, original, sections)
    assert exports.build_bundle(journal, stale)["component_metadata"]["by_status"] == {"stale": 1}
    sections["inventory"].pop("component:lib")
    absent = publish(journal, stale, sections)
    assert exports.build_bundle(journal, absent)["component_metadata"]["by_status"] == {"absent": 1}
    sections = copy.deepcopy(current(journal))
    sections["inventory"]["component:lib"] = {"bom-ref": "lib", "name": "lib", "version": "1"}
    other = publish(journal, absent, sections, version="7.1.2")
    assert exports.build_bundle(journal, other)["component_metadata"]["by_status"] == {
        "out_of_scope": 1
    }
    assert exports.build_bundle(journal, original) == before


def test_register_includes_all_nonfinding_occurrences_without_http_page_truncation(journal):
    seed(journal)
    save(journal, data(journal))
    parent = head(journal)
    sections = copy.deepcopy(current(journal))
    template = read(journal)
    revisions = []
    sections["vulnerabilities"] = {}
    for index in range(205):
        ref = f"nonfinding-{index}"
        component = {"bom-ref": ref, "name": ref, "version": "1"}
        sections["inventory"]["component:" + ref] = component
        payload = {
            **copy.deepcopy(template["payload"]),
            "component_ref": ref,
            "identity_fingerprint": identity_fingerprint(component),
        }
        revision = journal.store(payload)
        revisions.append(revision)
        sections["history"][metadata_key(ref)] = {
            **copy.deepcopy(sections["history"][metadata_key("lib")]),
            "revision": revision,
            "payload": payload,
        }
    state = publish(journal, parent, sections, artifacts=revisions)
    bundle = exports.build_bundle(journal, state)
    assert bundle["findings"] == []
    assert bundle["component_metadata"]["total"] == 206
    assert len(bundle["component_metadata"]["items"]) == 206
    assert bundle["component_metadata"]["by_status"] == {"current": 206}
    assert bundle["component_metadata"]["next_offset"] is None


def test_existing_issued_bytes_survive_register_upgrade_and_new_state_identifies_serializer(
    journal, monkeypatch
):
    seed(journal)
    save(journal, data(journal))
    selected = head(journal)
    original_builder = exports.build_bundle

    def old_builder(*args):
        result = original_builder(*args)
        result.pop("component_metadata", None)
        return result

    with monkeypatch.context() as previous:
        previous.setattr(exports, "build_bundle", old_builder)
        issued = issue_export(
            journal,
            project_id="project",
            actor_id="consumer",
            state=selected,
            kind="knowledge-bundle",
        )
    original_bytes = journal.objects.read(issued["files"]["bundle.json"]["sha256"])
    assert issued["serializer_id"] == "dtvp.knowledge-bundle-serializer/1"
    assert b'"component_metadata"' not in original_bytes
    assert "component_metadata" in exports.build_bundle(journal, selected)
    replay = issue_export(
        journal, project_id="project", actor_id="consumer", state=selected, kind="knowledge-bundle"
    )
    assert replay == issued
    assert journal.objects.read(replay["files"]["bundle.json"]["sha256"]) == original_bytes
    changed = data(
        journal, request_id="support-update", expected_revision=read(journal)["revision"]
    )
    changed.annotations.support.end_of_life = date(2030, 12, 31)
    save(journal, changed)
    newer = issue_export(
        journal,
        project_id="project",
        actor_id="consumer",
        state=head(journal),
        kind="knowledge-bundle",
    )
    assert newer["serializer_id"] == "dtvp.knowledge-bundle-serializer/2"
    assert b'"component_metadata"' in journal.objects.read(newer["files"]["bundle.json"]["sha256"])
    assert journal.objects.read(issued["files"]["bundle.json"]["sha256"]) == original_bytes
    assert canonical(exports.build_bundle(journal, head(journal))) != original_bytes
