"""Saved views, their short codes, and default views (ADR 0015)."""

import json

import pytest

from dtvp import main
from dtvp.saved_view_services import (
    CODE_ALPHABET,
    CODE_LENGTH,
    SavedViewError,
    SavedViewStore,
    canonical_query,
    with_cutoff_basis,
)

QUERY = "lifecycle=OPEN&lifecycle=INCOMPLETE&cutoff=2026-03-01&sort=id&order=asc"


@pytest.fixture
def store(tmp_path):
    return SavedViewStore(str(tmp_path / "views.sqlite3"))


@pytest.fixture
def as_user(client, tmp_path, monkeypatch):
    """Switch the signed-in user; rita reviews, anna and alan analyse."""
    roles = tmp_path / "user_roles.json"
    roles.write_text(json.dumps({"rita": "REVIEWER", "anna": "ANALYST", "alan": "ANALYST"}))
    monkeypatch.setenv("USER_ROLES_PATH", str(roles))

    def switch(user):
        main.app.dependency_overrides[main.get_current_user] = lambda: user
        return client

    return switch


# -- the canonical query ------------------------------------------------------


def test_canonical_query_sorts_parameters_and_list_values():
    assert canonical_query("changes_requested=true") == "changes_requested=true"
    assert canonical_query("changes_requested=false") == ""
    assert canonical_query("?sort=id&lifecycle=OPEN&lifecycle=INCOMPLETE&q=+log4j+") == (
        "lifecycle=INCOMPLETE&lifecycle=OPEN&q=log4j&sort=id"
    )
    assert canonical_query("lifecycle=OPEN&new_findings=false&cutoff=30D") == (
        "cutoff=30d&lifecycle=OPEN"
    )
    assert canonical_query("awaiting_review=false") == "awaiting_review=false"
    assert canonical_query("") == ""


@pytest.mark.parametrize(
    "query, message",
    [
        ("group=CVE-1", "Unknown filter parameter: group"),
        ("attributed_before_days=7", "Unknown filter parameter"),
        ("cutoff=soon", "cutoff must be"),
        ("cutoff_mode=later", "cutoff_mode"),
        ("order=up", "order must be"),
        ("not_rescored=yes", "not_rescored must be true or false"),
        ("q=a&q=b", "q takes one value"),
        ("q=" + "x" * 5000, "limited to"),
    ],
)
def test_canonical_query_rejects_what_is_no_filter(query, message):
    with pytest.raises(SavedViewError) as error:
        canonical_query(query)
    assert message in str(error.value)
    assert error.value.status == 422


# -- the store --------------------------------------------------------------


def test_views_have_codes_from_the_alphabet_and_personal_views_stay_private(store):
    view = store.create(
        user="anna", role="ANALYST", name="Release 7.2", scope="personal",
        project="TestApp", query=QUERY,
    )
    assert len(view.code) == CODE_LENGTH and set(view.code) <= set(CODE_ALPHABET)
    assert view.query == canonical_query(QUERY)
    assert [v.code for v in store.list_for("anna", "TestApp")] == [view.code]
    assert store.list_for("alan", "TestApp") == []
    assert store.list_for("anna", "Other") == []
    # Anyone can open its code.
    assert store.get(view.code.upper()).code == view.code
    with pytest.raises(SavedViewError) as error:
        store.update(user="alan", role="ANALYST", code=view.code, changes={"name": "Mine"})
    assert error.value.status == 404


def test_global_views_are_for_reviewers_and_visible_to_all(store):
    with pytest.raises(SavedViewError) as error:
        store.create(user="anna", role="ANALYST", name="Team", scope="global", project=None, query="")
    assert error.value.status == 403
    view = store.create(user="rita", role="REVIEWER", name="Team", scope="global", project=None, query="q=x")
    assert [v.code for v in store.list_for("anna", "Any")] == [view.code]
    assert not view.public("anna", "ANALYST")["editable"]
    with pytest.raises(SavedViewError) as error:
        store.delete(user="anna", role="ANALYST", code=view.code)
    assert error.value.status == 403
    renamed = store.update(user="rita", role="REVIEWER", code=view.code, changes={"name": "All teams"})
    assert renamed.name == "All teams" and renamed.updated_by == "rita"


def test_a_reviewer_shares_a_personal_view_globally(store):
    view = store.create(user="rita", role="REVIEWER", name="Mine", scope="personal", project=None, query="")
    shared = store.update(user="rita", role="REVIEWER", code=view.code, changes={"scope": "global"})
    assert shared.scope == "global" and shared.code == view.code
    analyst_view = store.create(user="anna", role="ANALYST", name="Mine", scope="personal", project=None, query="")
    with pytest.raises(SavedViewError) as error:
        store.update(user="anna", role="ANALYST", code=analyst_view.code, changes={"scope": "global"})
    assert error.value.status == 403
    with pytest.raises(SavedViewError):
        store.update(user="rita", role="REVIEWER", code=shared.code, changes={"scope": "personal"})


def test_names_are_unique_per_owner_and_project(store):
    store.create(user="anna", role="ANALYST", name="Release", scope="personal", project="A", query="")
    with pytest.raises(SavedViewError) as error:
        store.create(user="anna", role="ANALYST", name=" release ", scope="personal", project="A", query="")
    assert error.value.status == 409
    store.create(user="anna", role="ANALYST", name="Release", scope="personal", project="B", query="")
    store.create(user="alan", role="ANALYST", name="Release", scope="personal", project="A", query="")


def test_a_view_with_a_cutoff_keeps_the_basis_in_effect(store):
    assert canonical_query("cutoff=2026-03-01&cutoff_basis=ATTRIBUTED") == (
        "cutoff=2026-03-01&cutoff_basis=attributed"
    )
    with pytest.raises(SavedViewError):
        canonical_query("cutoff=2026-03-01&cutoff_basis=attributed_version")
    assert with_cutoff_basis("cutoff=2026-03-01", "published") == "cutoff=2026-03-01&cutoff_basis=published"
    assert with_cutoff_basis("cutoff=2026-03-01&cutoff_basis=attributed", "published") == (
        "cutoff=2026-03-01&cutoff_basis=attributed"
    )
    assert with_cutoff_basis("q=x", "published") == "q=x"
    view = store.create(
        user="anna", role="ANALYST", name="Freeze", scope="personal", project=None,
        query="cutoff=2026-03-01", default_cutoff_basis="published",
    )
    assert view.query == "cutoff=2026-03-01&cutoff_basis=published"
    updated = store.update(
        user="anna", role="ANALYST", code=view.code,
        changes={"query": "cutoff=2026-04-01&cutoff_basis=attributed"}, default_cutoff_basis="published",
    )
    assert updated.query == "cutoff=2026-04-01&cutoff_basis=attributed"


def test_default_precedence_user_project_user_all_role_project_role_all(store):
    def view(user, role, name, scope="personal", project=None):
        return store.create(user=user, role=role, name=name, scope=scope, project=project, query=f"q={name}")

    role_all = view("rita", "REVIEWER", "role-all", "global")
    role_project = view("rita", "REVIEWER", "role-project", "global", "P")
    user_all = view("anna", "ANALYST", "user-all")
    user_project = view("anna", "ANALYST", "user-project", project="P")

    def effective():
        return store.defaults_for("anna", "ANALYST", "P")["effective"]

    assert effective()["source"] == "builtin"
    store.set_default(user="rita", role="REVIEWER", target="role", target_role="analyst", project=None, code=role_all.code)
    assert effective()["code"] == role_all.code and effective()["source"] == "role"
    store.set_default(user="rita", role="REVIEWER", target="role", target_role="ANALYST", project="P", code=role_project.code)
    assert effective()["code"] == role_project.code
    store.set_default(user="anna", role="ANALYST", target="user", target_role=None, project=None, code=user_all.code)
    assert effective()["code"] == user_all.code and effective()["source"] == "user"
    store.set_default(user="anna", role="ANALYST", target="user", target_role=None, project="P", code=user_project.code)
    assert effective() == {
        "source": "user", "code": user_project.code, "query": "q=user-project", "name": "user-project",
    }
    # Reviewers do not get the analysts' default; other projects skip the
    # project defaults.
    assert store.defaults_for("rita", "REVIEWER", "P")["effective"]["source"] == "builtin"
    assert store.defaults_for("anna", "ANALYST", "Q")["effective"]["code"] == user_all.code
    # Deleting a view removes the defaults that name it; clearing works too.
    store.delete(user="anna", role="ANALYST", code=user_project.code)
    assert effective()["code"] == user_all.code
    store.set_default(user="anna", role="ANALYST", target="user", target_role=None, project=None, code=None)
    assert effective()["code"] == role_project.code


def test_default_rules(store):
    personal = store.create(user="rita", role="REVIEWER", name="mine", scope="personal", project=None, query="")
    other = store.create(user="alan", role="ANALYST", name="alans", scope="personal", project=None, query="")
    scoped = store.create(user="anna", role="ANALYST", name="p-only", scope="personal", project="P", query="")
    cases = [
        (dict(user="anna", role="ANALYST", target="role", target_role="ANALYST", project=None, code=personal.code), 403),
        (dict(user="rita", role="REVIEWER", target="role", target_role="ANALYST", project=None, code=personal.code), 422),
        (dict(user="rita", role="REVIEWER", target="role", target_role="ADMIN", project=None, code=None), 422),
        (dict(user="anna", role="ANALYST", target="user", target_role=None, project=None, code=other.code), 404),
        (dict(user="anna", role="ANALYST", target="user", target_role=None, project="Q", code=scoped.code), 422),
    ]
    for kwargs, status in cases:
        with pytest.raises(SavedViewError) as error:
            store.set_default(**kwargs)
        assert error.value.status == status, kwargs


# -- the API ----------------------------------------------------------------


def test_api_crud_permissions_codes_and_defaults(as_user):
    anna = as_user("anna")
    created = anna.post("/api/views", json={"name": "Release", "project": "TestApp", "query": QUERY})
    assert created.status_code == 201
    code = created.json()["code"]
    assert created.json()["editable"] is True
    assert anna.post("/api/views", json={"name": "x", "query": "group=1"}).status_code == 422
    assert anna.post("/api/views", json={"name": "x", "query": "", "extra": 1}).status_code == 422
    assert anna.post("/api/views", json={"name": "Team", "scope": "global"}).status_code == 403

    listing = anna.get("/api/views", params={"project": "TestApp"}).json()
    assert [view["code"] for view in listing["views"]] == [code]
    assert listing["can_manage_global"] is False
    assert listing["defaults"]["effective"]["source"] == "builtin"

    assert anna.put("/api/views/defaults", json={"project": "TestApp", "code": code}).json()[
        "effective"
    ]["code"] == code
    assert anna.patch(f"/api/views/{code}", json={"name": "Release 7.2"}).json()["name"] == "Release 7.2"

    # Unsaved filters have no short code.
    assert anna.post("/api/views/links", json={"project": "TestApp", "query": QUERY}).status_code in (404, 405)

    alan = as_user("alan")
    # Any signed-in user opens a view's code, also of a personal view.
    resolved = alan.get(f"/api/views/{code}")
    assert resolved.status_code == 200 and resolved.json()["project"] == "TestApp"
    # Saved through the API, a view with a cutoff keeps the basis in effect.
    assert resolved.json()["query"].endswith("cutoff_basis=published&lifecycle=INCOMPLETE&lifecycle=OPEN&order=asc&sort=id")
    assert alan.get("/api/views/zzzzzzzz").status_code == 404
    assert alan.patch(f"/api/views/{code}", json={"name": "Mine"}).status_code == 404
    assert alan.delete(f"/api/views/{code}").status_code == 404

    rita = as_user("rita")
    shared = rita.post("/api/views", json={"name": "Release freeze", "scope": "global", "query": "cutoff=2026-03-01"})
    assert shared.status_code == 201
    assert rita.put(
        "/api/views/defaults",
        json={"target": "role", "role": "ANALYST", "code": shared.json()["code"]},
    ).status_code == 200
    alan = as_user("alan")
    effective = alan.get("/api/views", params={"project": "Other"}).json()["defaults"]["effective"]
    assert effective == {
        "source": "role", "code": shared.json()["code"],
        "query": "cutoff=2026-03-01&cutoff_basis=published", "name": "Release freeze",
    }
    assert alan.delete(f"/api/views/{shared.json()['code']}").status_code == 403

    anna = as_user("anna")
    assert anna.delete(f"/api/views/{code}").status_code == 200
    assert anna.get("/api/views", params={"project": "TestApp"}).json()["defaults"]["effective"]["code"] == shared.json()["code"]
