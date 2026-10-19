"""CPE policy previews remain non-publishing and explicit replacements replay exactly."""

from tests.conftest import login
from tests.test_knowledge_api import app as knowledge_app
from tests.test_knowledge_api import product

app = knowledge_app


def path(project, suffix=""):
    return f"/api/v1/projects/{project}/cpe{suffix}"


def configuration(expected=None, request_id="configure-cpe"):
    return {
        "request_id": request_id,
        "expected": expected,
        "catalog": [
            {
                "purl": "pkg:npm/example",
                "cpe": "cpe:2.3:a:example:example:*:*:*:*:*:*:*:*",
                "source": "supplied-dictionary",
            }
        ],
        "rules": {
            "pkg:npm/alias": {
                "target_purl": "pkg:npm/example",
                "source": "organization",
                "reason": "Reviewed explicit upstream package alias",
            }
        },
    }


def test_preview_is_deterministic_without_journal_writes_and_matches_publication(analyst, app):
    project = product(analyst)
    login(analyst, "administrator")
    before = app.state.knowledge.head()
    data = configuration()
    result = analyst.post(path(project, "/preview"), json=data)
    assert result.status_code == 200, result.text
    preview = result.json()
    assert not preview["committed"] and preview["policy_state"] is None
    assert preview["changes"] == dict(
        catalog_added=1, catalog_removed=0, rules_added=1, rules_removed=0, rules_changed=0
    )
    assert analyst.post(path(project, "/preview"), json=data).json() == preview
    assert app.state.knowledge.head() == before
    assert analyst.get(path(project, "/editor")).json()["capabilities"] == ["configure"]
    result = analyst.put(path(project), json=data)
    assert result.status_code == 201, result.text
    saved = analyst.get(path(project, "/editor")).json()
    assert saved["configuration"]["catalog"] == preview["configuration"]["catalog"]
    assert saved["configuration"]["rules"] == preview["configuration"]["rules"]
    assert analyst.put(path(project), json=data).json() == result.json()


def test_exact_pin_replacement_delta_and_receipt_replay_after_new_policy(analyst, app):
    project = product(analyst)
    login(analyst, "administrator")
    first = configuration()
    receipt = analyst.put(path(project), json=first)
    assert receipt.status_code == 201
    current = analyst.get(path(project, "/editor")).json()["policy_state"]
    replacement = configuration(current, "replace-cpe")
    replacement["catalog"] = []
    replacement["rules"]["pkg:npm/alias"]["reason"] = "New explicitly reviewed rationale"
    preview = analyst.post(path(project, "/preview"), json=replacement).json()
    assert preview["changes"]["catalog_removed"] == 1
    assert preview["changes"]["rules_changed"] == 1
    assert analyst.put(path(project), json=replacement).status_code == 201
    before = app.state.knowledge.head()
    assert analyst.post(path(project, "/preview"), json=first).status_code == 409
    replay = analyst.put(path(project), json=first).json()
    assert {key: value for key, value in replay.items() if key != "projected_sequence"} == {
        key: value for key, value in receipt.json().items() if key != "projected_sequence"
    }
    assert analyst.put(path(project), json={**first, "catalog": []}).status_code == 409
    assert app.state.knowledge.head() == before


def test_readers_and_other_projects_cannot_configure_and_invalid_inputs_never_write(analyst, app):
    project = product(analyst)
    login(analyst, "viewer")
    assert analyst.get(path(project, "/editor")).json()["capabilities"] == []
    assert analyst.post(path(project, "/preview"), json=configuration()).status_code in {403, 404}
    assert analyst.put(path(project), json=configuration()).status_code in {403, 404}
    login(analyst, "operations")
    assert analyst.get(path(project, "/editor")).status_code == 404
    login(analyst, "administrator")
    before = app.state.knowledge.head()
    invalid = configuration()
    invalid["catalog"][0]["cpe"] = "unverified-free-text"
    assert analyst.post(path(project, "/preview"), json=invalid).status_code == 422
    invalid = configuration()
    invalid["rules"]["pkg:npm/alias"]["cpe"] = invalid["catalog"][0]["cpe"]
    assert analyst.post(path(project, "/preview"), json=invalid).status_code == 422
    assert app.state.knowledge.head() == before
