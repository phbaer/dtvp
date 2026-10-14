from tests.conftest import login


def test_catalog_search_pages_scope_and_review_filters(analyst):
    login(analyst, "administrator")
    result = analyst.post(
        "/api/v2/playground/scale", json={"projects": 60, "findings_per_project": 3}
    )
    assert result.status_code == 200, result.text
    assert result.json()["created_projects"] == 60
    assert (
        analyst.post(
            "/api/v2/playground/scale", json={"projects": 60, "findings_per_project": 3}
        ).json()["created_projects"]
        == 0
    )
    login(analyst)
    seen, cursor = [], ""
    while True:
        page = analyst.get("/api/v2/catalog/projects", params={"cursor": cursor, "limit": 7}).json()
        assert len(page["items"]) <= 7
        seen.extend(row["id"] for row in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 61
    tail = analyst.get("/api/v2/catalog/projects?q=0060").json()["items"]
    assert len(tail) == 1 and tail[0]["finding_count"] == 3
    release = analyst.get(f"/api/v2/catalog/projects/{tail[0]['id']}/releases").json()["items"][0]
    first = analyst.get(
        "/api/v2/findings", params={"project_id": tail[0]["id"], "sort": "identifier", "limit": 1}
    ).json()
    second = analyst.get(
        "/api/v2/findings",
        params={
            "project_id": tail[0]["id"],
            "sort": "identifier",
            "limit": 1,
            "cursor": first["next_cursor"],
        },
    ).json()
    assert first["items"][0]["identifier"] < second["items"][0]["identifier"]
    assert (
        analyst.get(
            "/api/v2/findings", params={"sort": "identifier", "cursor": first["next_cursor"]}
        ).status_code
        == 422
    )
    assert (
        len(analyst.get("/api/v2/findings", params={"q": "Scale product 0060"}).json()["items"])
        == 3
    )
    assert analyst.get("/api/v2/findings?owner=Nonexistent").json()["items"] == []
    assert (
        len(analyst.get(f"/api/v2/releases/{release['id']}/components?q=0002").json()["items"]) == 1
    )
    login(analyst, "operations")
    assert analyst.get("/api/v2/catalog/projects?q=Scale").json()["items"] == []
    assert analyst.get(f"/api/v2/catalog/projects/{tail[0]['id']}/releases").status_code == 404
    assert analyst.get(f"/api/v2/findings?project_id={tail[0]['id']}").status_code == 404


def test_catalog_cursors_are_bound_to_query(analyst):
    login(analyst, "administrator")
    page = analyst.get("/api/v2/catalog/projects?limit=1").json()
    assert page["next_cursor"]
    assert (
        analyst.get(
            "/api/v2/catalog/projects", params={"q": "Worker", "cursor": page["next_cursor"]}
        ).status_code
        == 422
    )
    assert analyst.get("/api/v2/catalog/projects?cursor=garbage").status_code == 422


def test_release_catalog_preserves_latest_first_and_search_pagination(analyst, release_id):
    project_id = analyst.get("/api/v2/projects").json()[0]["id"]
    for version in ["2.0.0", "3.0.0", "4.0.0"]:
        assert (
            analyst.post(
                f"/api/v2/projects/{project_id}/releases", json={"version": version}
            ).status_code
            == 201
        )
    first = analyst.get(f"/api/v2/catalog/projects/{project_id}/releases?limit=1").json()
    assert first["items"][0]["version"] == "4.0.0"
    second = analyst.get(
        f"/api/v2/catalog/projects/{project_id}/releases",
        params={"limit": 1, "cursor": first["next_cursor"]},
    ).json()
    assert second["items"][0]["version"] == "3.0.0"
    assert (
        analyst.get(f"/api/v2/catalog/projects/{project_id}/releases?q=2.0").json()["items"][0][
            "version"
        ]
        == "2.0.0"
    )
