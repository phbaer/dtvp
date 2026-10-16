"""Cached historical bytes never cache current HTTP access permission."""

from sqlalchemy import delete, select

from dtvp.models import Membership, User
from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import body, imported
from tests.test_workflow_api import setup, url, workspace

app = knowledge_app


def test_cached_comparison_rechecks_changed_actor_and_revoked_membership(analyst, app, bom):
    project, _ = setup(analyst, bom)
    first = workspace(analyst, project)["state"]
    second = imported(
        analyst, project, "7.1.2", body(bom, request_id="comparison-cache", predecessor=first)
    )
    path = url(project, "/compare/details")
    params = {"before": first, "after": second, "limit": 1}
    login(analyst, "viewer")
    response = analyst.get(path, params=params)
    assert response.status_code == 200, response.text
    assert analyst.get(path, params=params).json() == response.json()
    with app.state.sessions.begin() as db:
        viewer = db.scalar(select(User).where(User.subject == "viewer"))
        db.execute(delete(Membership).where(Membership.user_id == viewer.id))
    assert analyst.get(path, params=params).status_code == 404
    login(analyst, "operations")
    assert analyst.get(path, params=params).status_code == 404
    login(analyst, "administrator")
    assert analyst.get(path, params=params).json() == response.json()
