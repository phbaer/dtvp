"""A running process is not ready while its native projection lags the journal."""

from sqlalchemy import delete, select, update

from dtvp.knowledge.journal import CorruptJournal
from dtvp.knowledge.projection import catch_up, cursor
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product

app = knowledge_app


def checkpoint(application):
    with application.state.engine.connect() as connection:
        return tuple(connection.execute(select(cursor)).one())


def test_readiness_detects_lag_without_mutating_or_repairing(analyst, app, bom):
    assert analyst.get("/readyz").json() == {"status": "ready"}
    project_id = product(analyst)
    imported(analyst, project_id, "7.1.1", body(bom))
    journal = app.state.knowledge
    head = journal.head()
    assert analyst.get("/readyz").status_code == 200
    with app.state.engine.begin() as connection:
        connection.execute(update(cursor).values(publication_sha=None, sequence=0))
    lagging = checkpoint(app)
    for _ in range(2):
        response = analyst.get("/readyz")
        assert response.status_code == 503, response.text
        assert response.json() == {"detail": "Native knowledge projection is not current"}
        assert analyst.get("/healthz").json() == {"status": "ok"}
        assert checkpoint(app) == lagging
        assert journal.head() == head
    catch_up(app.state.engine, journal)
    assert analyst.get("/readyz").json() == {"status": "ready"}


def test_missing_checkpoint_wrong_sequence_and_corruption_fail_closed(
    analyst, app, bom, monkeypatch
):
    imported(analyst, product(analyst), "7.1.1", body(bom))
    engine, journal = app.state.engine, app.state.knowledge
    with engine.begin() as connection:
        connection.execute(update(cursor).values(sequence=999999))
    assert analyst.get("/readyz").status_code == 503
    with engine.begin() as connection:
        connection.execute(delete(cursor))
    assert analyst.get("/readyz").status_code == 503
    # Rebuild requires its checkpoint row; readiness never fabricates one.
    with engine.begin() as connection:
        connection.execute(cursor.insert().values(id=1, sequence=0, publication_sha=None))
    catch_up(engine, journal, rebuild=True)
    assert analyst.get("/readyz").status_code == 200
    original = journal.load

    def corrupt(sha, *args, **kwargs):
        if sha == journal.head():
            raise CorruptJournal("Internal object details must not be exposed")
        return original(sha, *args, **kwargs)

    monkeypatch.setattr(journal, "load", corrupt)
    response = analyst.get("/readyz")
    assert response.status_code == 503
    assert "Internal object" not in response.text
    assert analyst.get("/healthz").status_code == 200
