"""A legacy SQL reset must never orphan authoritative journal knowledge."""

from sqlalchemy import select

from dtvp.knowledge.projection import cursor, heads, records
from dtvp.models import Project, User, Workspace
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported, product

app = knowledge_app


def projection(app):
    with app.state.engine.connect() as connection:
        return {
            table.name: connection.execute(select(table)).all()
            for table in (cursor, heads, records)
        }


def identities(app):
    with app.state.sessions() as session:
        return {
            model.__tablename__: sorted(session.scalars(select(model.id)))
            for model in (User, Project, Workspace)
        }


def test_legacy_reset_preserves_empty_projection_checkpoint_and_future_import_works(
    analyst, app, bom
):
    login(analyst, "administrator")
    before = projection(app)
    assert len(before["knowledge_cursor"]) == 1
    assert app.state.knowledge.head() is None
    response = analyst.post("/api/v2/playground/reset")
    assert response.status_code == 200, response.text
    assert response.json()["sign_in_required"]
    assert projection(app) == before
    # Reset invalidates the old fixture session. A new login can use v3 without
    # the formerly missing-cursor/projection-pending failure.
    assert analyst.get("/api/v2/me").status_code == 401
    login(analyst)
    project_id = product(analyst)
    state = imported(analyst, project_id, "7.1.1", body(bom))
    inventory = analyst.get(f"/api/v3/projects/{project_id}/versions/7.1.1/inventory")
    assert inventory.status_code == 200, inventory.text
    assert inventory.json()["state"] == state
    assert projection(app)["knowledge_heads"]


def test_nonempty_journal_refuses_reset_without_changing_identity_projection_or_access(
    analyst, app, bom
):
    project_id = product(analyst)
    state = imported(analyst, project_id, "7.1.1", body(bom))
    login(analyst, "administrator")
    before_head = app.state.knowledge.head()
    before_projection = projection(app)
    before_identities = identities(app)
    project_list = analyst.get("/api/v2/projects").json()
    response = analyst.post("/api/v2/playground/reset")
    assert response.status_code == 409, response.text
    assert "Nothing was reset" in response.json()["detail"]
    assert app.state.knowledge.head() == before_head
    assert projection(app) == before_projection
    assert identities(app) == before_identities
    assert analyst.get("/api/v2/projects").json() == project_list
    assert (
        analyst.get(f"/api/v3/projects/{project_id}/versions/7.1.1/inventory").json()["state"]
        == state
    )
    # Existing credentials and journal pins remain usable; no surprise logout.
    assert analyst.get("/api/v2/me").status_code == 200
    latest = imported(
        analyst, project_id, "7.1.1", body(bom, request_id="next", expected=state, build_number=2)
    )
    assert latest != state


def test_reset_authority_checks_precede_any_data_change(analyst, app):
    before = projection(app)
    users = identities(app)
    assert analyst.post("/api/v2/playground/reset").status_code == 403
    assert projection(app) == before
    assert identities(app) == users
