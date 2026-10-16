"""Stopped-writer SQL roots preserve checkpoints without exposing row contents."""

import os
import uuid

import pytest
from sqlalchemy import Column, MetaData, String, Table, create_engine, insert, text, update
from sqlalchemy.engine import make_url

from dtvp.knowledge import operational_roots as module
from dtvp.knowledge.journal import CorruptJournal, Journal
from dtvp.models import Base, Job, Project, User, Workspace
from dtvp.storage import canonical, digest


@pytest.fixture(params=["sqlite", "postgresql"])
def database(request):
    url = "sqlite:///:memory:"
    if request.param == "postgresql":
        url = os.environ.get("DTVP_TEST_DATABASE_URL")
        if not url:
            pytest.skip("Optional PostgreSQL operational-root checks require disposable database")
        parsed = make_url(url)
        if parsed.get_backend_name() != "postgresql" or not parsed.database.endswith("_test"):
            pytest.fail("Operational-root PostgreSQL checks require a disposable _test database")
    engine = create_engine(url)
    with engine.connect() as connection:
        transaction = connection.begin()
        if request.param == "postgresql":
            schema = "operational_roots_" + uuid.uuid4().hex
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
        Base.metadata.create_all(connection)
        version = Table(
            "alembic_version", MetaData(), Column("version_num", String(32), primary_key=True)
        )
        version.create(connection)
        connection.execute(insert(version).values(version_num="0005"))
        connection.execute(insert(Workspace).values(id="workspace", name="synthetic"))
        connection.execute(
            insert(User).values(id="user", issuer="synthetic", subject="user", name="user")
        )
        connection.execute(
            insert(Project).values(id="project", workspace_id="workspace", name="synthetic")
        )
        try:
            yield connection
        finally:
            transaction.rollback()
    engine.dispose()


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def job(connection, *, payload=None, result=None, status="failed", kind="import-dt-native"):
    identity = uuid.uuid4().hex
    connection.execute(
        insert(Job).values(
            id=identity,
            project_id="project",
            actor_id="user",
            kind=kind,
            status=status,
            payload=payload or {},
            result=result or {},
        )
    )
    return identity


def test_snapshot_is_deterministic_secret_free_and_covers_all_statuses(database, journal):
    hashes = []
    secret = "do-not-print-credential-or-correlation-nonce"
    for status in (
        "queued",
        "running",
        "failed",
        "import_pending",
        "succeeded",
        "cancelled",
        "submission_unknown",
    ):
        sha = journal.store({"status": status})
        hashes.append(sha)
        job(database, payload={"capture_sha256": sha, "secret": secret}, status=status)
    first = module.snapshot_operational_roots(database, journal)
    assert module.snapshot_operational_roots(database, journal) == first
    assert first["roots"] == sorted(hashes)
    assert first["table_counts"]["jobs"] == 7
    assert len(first["table_counts"]) == 24
    assert secret not in str(first)
    assert first["schema_revision"] == "0005"
    database.execute(update(Project).values(metadata_json={"unrelated_change": True}))
    assert (
        module.snapshot_operational_roots(database, journal)["database_digest"]
        != first["database_digest"]
    )


def test_nested_keys_embedded_tokens_and_unknown_hashes(database, journal):
    sha = journal.objects.put(b"retained arbitrary evidence")
    absent = "f" * 64
    job(
        database,
        kind="unknown-future-legacy-kind",
        payload={
            sha: [{"url": "https://synthetic.invalid/sha256:" + sha.upper(), "missing": absent}],
        },
    )
    assert module.snapshot_operational_roots(database, journal)["roots"] == [sha]


@pytest.mark.parametrize(
    "field", ["capture_sha256", "progress_sha256", "report_sha256", "raw_artifact_shas"]
)
@pytest.mark.parametrize("location", ["payload", "result"])
def test_missing_known_checkpoints_fail_closed(database, journal, field, location):
    value = ["a" * 64] if field == "raw_artifact_shas" else "a" * 64
    job(database, **{location: {field: value}}, status="cancelled")
    with pytest.raises(CorruptJournal, match="missing or corrupt"):
        module.snapshot_operational_roots(database, journal)


def test_corrupt_checkpoint_fails_closed(database, journal):
    sha = journal.objects.put(b"retained")
    job(database, payload={"capture_sha256": sha})
    journal.objects.path(sha).write_bytes(b"corrupt")
    with pytest.raises(CorruptJournal, match="missing or corrupt"):
        module.snapshot_operational_roots(database, journal)


def test_followup_correlations_and_non_object_submission_fingerprint(database, journal):
    issued = journal.store({"issued": True})
    report = journal.store({"report": True})
    wire = {"question": "synthetic", "user_guidance": ""}
    job(
        database,
        kind="analyse-native",
        payload={
            "correlation": {
                "issued_receipt_sha256": issued,
                "submission_sha256": digest(canonical(wire)),
            },
            "follow_up": {
                "parent_report_sha256": report,
                "wire_request": wire,
                "parent_correlation": {"issued_receipt_sha256": issued},
            },
        },
        status="succeeded",
    )
    assert module.snapshot_operational_roots(database, journal)["roots"] == sorted([issued, report])


def test_missing_issued_receipt_and_bad_submission_rejected(database, journal):
    job(
        database,
        kind="analyse-native",
        payload={"correlation": {"issued_receipt_sha256": "d" * 64}},
    )
    with pytest.raises(CorruptJournal, match="missing or corrupt"):
        module.snapshot_operational_roots(database, journal)


def test_bad_followup_fingerprint_is_not_treated_as_missing_artifact(database, journal):
    job(
        database,
        kind="analyse-native",
        payload={
            "correlation": {"submission_sha256": "e" * 64},
            "follow_up": {"wire_request": {"question": "synthetic"}},
        },
    )
    with pytest.raises(CorruptJournal, match="fingerprint differs"):
        module.snapshot_operational_roots(database, journal)


@pytest.mark.parametrize("value", [None, 1, "not-a-sha", {"unexpected": "value"}])
def test_malformed_known_checkpoint_fails_closed(database, journal, value):
    job(database, result={"capture_sha256": value})
    with pytest.raises(CorruptJournal, match="Invalid retained operational"):
        module.snapshot_operational_roots(database, journal)


@pytest.mark.parametrize(
    "mutation", ["extra_table", "extra_column", "missing_table", "view", "revision"]
)
def test_unknown_or_stale_schema_fails_closed(database, journal, mutation):
    if mutation == "extra_table":
        database.execute(text("CREATE TABLE unsupported (id INTEGER PRIMARY KEY)"))
    elif mutation == "extra_column":
        database.execute(text("ALTER TABLE jobs ADD COLUMN unsupported VARCHAR(64)"))
    elif mutation == "missing_table":
        database.execute(text("DROP TABLE knowledge_cursor"))
    elif mutation == "view":
        database.execute(text("CREATE VIEW unsupported AS SELECT id FROM jobs"))
    else:
        database.execute(text("UPDATE alembic_version SET version_num='old'"))
    with pytest.raises(ValueError, match="schema|columns|revision"):
        module.snapshot_operational_roots(database, journal)


def test_row_and_byte_bounds(database, journal, monkeypatch):
    monkeypatch.setattr(module, "MAX_ROWS", 1)
    with pytest.raises(ValueError, match="row bound"):
        module.snapshot_operational_roots(database, journal)
    monkeypatch.setattr(module, "MAX_ROWS", 1_000_000)
    monkeypatch.setattr(module, "MAX_BYTES", 1)
    with pytest.raises(ValueError, match="byte bound"):
        module.snapshot_operational_roots(database, journal)


@pytest.mark.parametrize("missing", [None, "policy", "source", "target", "basis", "artifact_sha"])
def test_synchronization_inputs_and_frozen_proposals_are_strict_roots(database, journal, missing):
    objects = {
        key: journal.store({"object": key})
        for key in ("policy", "source", "target", "basis", "artifact_sha")
    }
    values = dict(objects)
    if missing:
        values[missing] = "e" * 64
    job(
        database,
        kind="propose-sync-native",
        status="cancelled",
        payload={
            "inputs": {
                "policy": values["policy"],
                "source": values["source"],
                "target": values["target"],
                "relationship": {"basis": values["basis"]},
            }
        },
        result={"artifact_sha": values["artifact_sha"]},
    )
    if missing:
        with pytest.raises(CorruptJournal, match="missing or corrupt"):
            module.snapshot_operational_roots(database, journal)
    else:
        assert module.snapshot_operational_roots(database, journal)["roots"] == sorted(
            objects.values()
        )
