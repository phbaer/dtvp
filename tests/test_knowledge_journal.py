from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import insert, select

from dtvp.db import engine_for
from dtvp.knowledge.journal import SECTIONS, Conflict, CorruptJournal, Journal, Ref, Update
from dtvp.knowledge.projection import catch_up, cursor, heads, records
from dtvp.storage import canonical, digest


def state(journal, version="7.1.1", parent=None, **changes):
    sections = {name: {} for name in SECTIONS}
    sections.update(changes)
    return journal.snapshot(
        project_id="product",
        version=version,
        actor_id="alice",
        reason="Test decision",
        parents=[parent] if parent else [],
        sections=sections,
    )


def publish(journal, target, *, expected=None, version="7.1.1", request_id="first"):
    return journal.publish(
        request_id=request_id,
        fingerprint=digest(canonical([request_id, target])),
        updates=[
            Update(ref=Ref(project_id="product", name=version), expected=expected, target=target)
        ],
    )


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


@pytest.fixture
def projection():
    engine = engine_for("sqlite:///:memory:")
    for table in (heads, records, cursor):
        table.create(engine)
    with engine.begin() as connection:
        connection.execute(insert(cursor).values(id=1, sequence=0))
    yield engine
    engine.dispose()


def test_complete_snapshots_share_unchanged_data_and_diff_across_versions(journal):
    first = state(
        journal,
        inventory={"component:a": {"version": "1"}},
        assessments={"a": {"reason": "Feature disabled"}},
    )
    second = state(
        journal,
        version="7.1.2",
        parent=first,
        inventory={"component:a": {"version": "2"}, "component:b": {"version": "1"}},
        assessments={"a": {"reason": "Feature disabled"}},
    )
    assert (
        journal.state(first).sections["assessments"]
        == journal.state(second).sections["assessments"]
    )
    assert journal.diff(first, second)["changes"] == {
        "inventory": {"added": ["component:b"], "removed": [], "changed": ["component:a"]}
    }
    third = state(journal, parent=first, inventory={})
    assert journal.diff(first, third)["changes"]["inventory"]["removed"] == ["component:a"]
    assert journal.load(journal.records(first, "assessments")["a"])["reason"] == "Feature disabled"


def test_multi_branch_publication_conflict_is_atomic_and_tags_are_immutable(journal):
    left, right = state(journal), state(journal, version="7.1.2")
    publish(journal, left)
    publish(journal, right, version="7.1.2", request_id="second")
    refs = journal.references()
    next_left = state(journal, parent=left)
    next_right = state(journal, version="7.1.2", parent=right)
    updates = [
        Update(ref=Ref(project_id="product", name="7.1.1"), expected=left, target=next_left),
        Update(ref=Ref(project_id="product", name="7.1.2"), expected=None, target=next_right),
    ]
    with pytest.raises(Conflict):
        journal.publish(request_id="conflict", fingerprint="a" * 64, updates=updates)
    assert journal.references() == refs
    updates[1] = updates[1].model_copy(update={"expected": right})
    journal.publish(request_id="both", fingerprint="b" * 64, updates=updates)
    tag = Ref(kind="tag", project_id="product", name="release/7.1.1")
    journal.publish(
        request_id="tag",
        fingerprint="c" * 64,
        updates=[Update(ref=tag, expected=None, target=left)],
    )
    with pytest.raises(Conflict):
        journal.publish(
            request_id="retag",
            fingerprint="d" * 64,
            updates=[Update(ref=tag, expected=left, target=next_left)],
        )
    assert journal.resolve(tag) == left


@pytest.mark.parametrize("after_replace", [False, True])
def test_retry_recovers_uncertain_commit_without_double_publication(
    journal, monkeypatch, after_replace
):
    target = state(journal)
    original = journal._replace_head

    def interrupted(sha):
        if after_replace:
            original(sha)
        raise OSError("Simulated process interruption")

    monkeypatch.setattr(journal, "_replace_head", interrupted)
    with pytest.raises(OSError):
        publish(journal, target)
    recovered = Journal(journal.root)
    if not after_replace:
        assert recovered.references() == {}
    receipt = publish(recovered, target)
    assert receipt[1].sequence == 1
    assert publish(recovered, target) == receipt
    assert len(list(recovered.publications())) == 1


def test_concurrent_writers_cannot_lose_updates(journal):
    first = state(journal)
    publish(journal, first)
    targets = [
        state(journal, parent=first, assessments={"a": {"value": value}}) for value in (1, 2)
    ]

    def attempt(item):
        index, target = item
        try:
            return publish(
                Journal(journal.root), target, expected=first, request_id=f"race-{index}"
            )
        except Conflict:
            return None

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(attempt, enumerate(targets)))
    assert sum(result is not None for result in results) == 1
    assert len(list(journal.publications())) == 2


def test_rebuild_preserves_drafts_reviews_and_handles_removed_components(journal, projection):
    first = state(
        journal,
        inventory={"a": {"version": "1"}},
        assessments={"draft": {"status": "draft", "reason": "Investigating"}},
        reviews={"old": {"assessment": "historical", "approved": True}},
    )
    publish(journal, first)
    catch_up(projection, journal)
    second = state(
        journal,
        parent=first,
        inventory={"b": {"version": "2"}},
        assessments={"draft": {"status": "draft", "reason": "Updated evidence"}},
        reviews={"old": {"assessment": "historical", "approved": True}},
    )
    publish(journal, second, expected=first, request_id="replacement")
    expected = catch_up(projection, journal)
    assert catch_up(projection, journal) == expected
    with projection.connect() as connection:
        before = connection.execute(select(records).order_by(records.c.section)).all()
        assert {row.record_key for row in before} == {"b", "draft", "old"}
    assert catch_up(projection, journal, rebuild=True) == expected
    with projection.connect() as connection:
        assert connection.execute(select(records).order_by(records.c.section)).all() == before


def test_projection_failure_rolls_back_checkpoint_and_retries(journal, projection, monkeypatch):
    import dtvp.knowledge.projection as module

    first = state(journal, inventory={"a": {"version": "1"}})
    publish(journal, first)
    original = module.apply_state

    def interrupted(*args):
        original(*args)
        raise RuntimeError("Process stopped before checkpoint")

    monkeypatch.setattr(module, "apply_state", interrupted)
    with pytest.raises(RuntimeError):
        catch_up(projection, journal)
    with projection.connect() as connection:
        assert connection.execute(select(heads)).all() == []
        assert connection.execute(select(cursor.c.sequence)).scalar() == 0
    monkeypatch.setattr(module, "apply_state", original)
    assert catch_up(projection, journal)["sequence"] == 1


def test_missing_head_or_corrupt_objects_fail_closed(journal, projection):
    first = state(journal, inventory={"a": {"version": "1"}})
    publish(journal, first)
    catch_up(projection, journal)
    sha = journal.records(first, "inventory")["a"]
    journal.objects.path(sha).write_bytes(b"changed")
    with pytest.raises((CorruptJournal, ValueError)):
        catch_up(projection, journal, rebuild=True)
    with projection.connect() as connection:
        assert connection.execute(select(heads.c.state_sha)).scalar() == first
    (journal.root / "HEAD").unlink()
    with pytest.raises(CorruptJournal, match="HEAD"):
        journal.head()


def test_projection_checkpoint_cannot_silently_move_to_unrelated_history(journal, projection):
    publish(journal, state(journal))
    catch_up(projection, journal)
    (journal.root / "HEAD").write_text("EMPTY\n")
    with pytest.raises(CorruptJournal, match="checkpoint"):
        catch_up(projection, journal)


def test_invalid_complete_state_and_non_json_numbers_are_rejected(journal):
    with pytest.raises(ValueError, match="every section"):
        journal.snapshot(project_id="p", version="v", actor_id="a", reason="test", sections={})
    with pytest.raises(ValueError):
        journal.store({"score": float("nan")})
    other = journal.snapshot(
        project_id="other",
        version="v",
        actor_id="a",
        reason="test",
        sections={name: {} for name in SECTIONS},
    )
    with pytest.raises(ValueError, match="same product"):
        journal.diff(state(journal), other)
