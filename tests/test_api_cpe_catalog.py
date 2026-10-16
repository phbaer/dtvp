"""Instance catalog access still requires current project read authorization."""

from sqlalchemy import delete, select

from dtvp.knowledge.cpe_catalog import Catalog
from dtvp.models import Membership, User
from tests.conftest import login
from tests.test_cpe_catalog import archive
from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, url

app = knowledge_app


def test_catalog_reads_are_optional_project_scoped_and_keep_human_configuration(
    analyst, app, bom, tmp_path
):
    project, _ = setup(analyst, bom)
    path = url(project, "/cpe/catalog")
    root = app.state.settings.artifact_dir / "cpe-catalog"
    assert analyst.get(path).json()["available"] is False
    assert not root.exists()
    source, meta = archive(tmp_path)
    catalog = Catalog(root)
    result = catalog.import_archive(source, meta)
    prior_journal = app.state.knowledge.head()
    status = analyst.get(path)
    assert status.status_code == 200 and status.json()["generation"] == result["generation"]
    page = analyst.get(path + "/search", params={"q": "catalog", "limit": 1})
    assert page.status_code == 200 and page.json()["total"] == 1
    exported = analyst.get(
        path + "/export", params={"q": "catalog", "generation": result["generation"]}
    )
    assert exported.status_code == 200 and len(exported.json()["dictionary"]) == 1
    assert app.state.knowledge.head() == prior_journal
    assert analyst.get(path + "/search", params={"q": "catalog", "limit": 201}).status_code == 422
    assert (
        analyst.get(
            path + "/search", params={"q": "catalog", "generation": "../unsafe"}
        ).status_code
        == 422
    )
    login(analyst, "viewer")
    assert analyst.get(path).status_code == 200
    with app.state.sessions.begin() as db:
        user = db.scalar(select(User).where(User.issuer == "playground", User.subject == "viewer"))
        db.execute(delete(Membership).where(Membership.user_id == user.id))
    assert analyst.get(path).status_code == 404
    assert analyst.get(path + "/search", params={"q": "catalog"}).status_code == 404
    assert analyst.get(path + "/export", params={"q": "catalog"}).status_code == 404
