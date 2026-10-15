"""Publication guards cover races after application-level policy reads."""

import pytest

from dtvp.knowledge.journal import Conflict, Journal, Ref, Update
from dtvp.knowledge.ownership import policy_ref
from tests.test_knowledge_journal import publish, state


def test_inventory_cannot_publish_using_a_policy_that_changed_after_read(tmp_path):
    journal = Journal(tmp_path / "journal")
    inventory = state(journal)
    policy = state(journal, version="@ownership")
    journal.publish(
        request_id="new-policy",
        fingerprint="a" * 64,
        updates=[Update(ref=policy_ref("product"), expected=None, target=policy)],
    )
    before = journal.head()
    with pytest.raises(Conflict):
        journal.publish(
            request_id="stale-inventory",
            fingerprint="b" * 64,
            updates=[
                Update(ref=Ref(project_id="product", name="7.1.1"), expected=None, target=inventory)
            ],
            checks=[(policy_ref("product"), None)],
        )
    assert journal.head() == before
    assert journal.resolve(Ref(project_id="product", name="7.1.1")) is None


def test_policy_cannot_miss_a_version_created_after_read(tmp_path):
    journal = Journal(tmp_path / "journal")
    first = state(journal)
    publish(journal, first)
    next_first = state(journal, parent=first)
    # This version appears after an administrator captured only 7.1.1.
    parallel = state(journal, version="7.1.2")
    publish(journal, parallel, version="7.1.2", request_id="parallel")
    policy = state(journal, version="@ownership")
    before = journal.head()
    with pytest.raises(Conflict):
        journal.publish(
            request_id="stale-policy",
            fingerprint="c" * 64,
            updates=[
                Update(ref=policy_ref("product"), expected=None, target=policy),
                Update(
                    ref=Ref(project_id="product", name="7.1.1"), expected=first, target=next_first
                ),
            ],
            branch_heads={"product": {"7.1.1": first}},
        )
    assert journal.head() == before
    assert journal.resolve(policy_ref("product")) is None
    assert journal.resolve(Ref(project_id="product", name="7.1.1")) == first


def test_context_expansion_limit_keeps_previous_inventory(analyst, monkeypatch):
    import dtvp.knowledge.ownership as ownership
    from tests.test_knowledge_api import body, imported, product
    from tests.test_knowledge_ownership import graph

    project_id = product(analyst)
    first = imported(analyst, project_id, "7.1.1", body(graph({"root": []})))
    monkeypatch.setattr(ownership, "MAX_CONTEXTS", 1)
    path = f"/api/v3/projects/{project_id}/versions/7.1.1"
    response = analyst.post(
        f"{path}/imports",
        json=body(
            graph({"root": ["X"], "X": []}),
            expected=first,
            request_id="too-many-contexts",
            build_number=2,
        ),
    )
    assert response.status_code == 422
    assert "context limit" in response.json()["detail"].lower()
    assert analyst.get(f"{path}/inventory").json()["state"] == first


def test_policy_projection_failure_retries_committed_transaction_once(analyst, monkeypatch):
    import dtvp.api_knowledge as api
    from tests.test_knowledge_api import body, imported
    from tests.test_knowledge_ownership import (
        administrator,
        current_policy,
        graph,
        policy_body,
        rule,
    )

    project_id, teams = administrator(analyst)
    imported(analyst, project_id, "7.1.1", body(graph({"root": ["X"], "X": []})))
    payload = policy_body(analyst, project_id, [rule("root", teams["Platform"])])
    original = api.catch_up

    def failed(*args):
        raise RuntimeError("Projection unavailable after authoritative publication")

    monkeypatch.setattr(api, "catch_up", failed)
    path = f"/api/v3/projects/{project_id}"
    first = analyst.put(f"{path}/ownership", json=payload)
    assert first.status_code == 202
    committed = current_policy(analyst, project_id)
    stale = analyst.get(f"{path}/versions/7.1.1/contexts").json()
    assert stale["projection_current"] is False
    assert stale["state"] != committed["versions"]["7.1.1"]
    monkeypatch.setattr(api, "catch_up", original)
    retry = analyst.put(f"{path}/ownership", json=payload)
    assert retry.status_code == 201
    assert retry.json()["publication"] == first.json()["publication"]
    assert current_policy(analyst, project_id) == committed
    current = analyst.get(f"{path}/versions/7.1.1/contexts").json()
    assert current["projection_current"] is True
    assert current["policy_state"] == committed["policy_state"]


def test_historical_context_is_readable_after_reassignment_with_current_permissions(analyst):
    from tests.conftest import login
    from tests.test_knowledge_api import body, imported
    from tests.test_knowledge_ownership import administrator, apply_policy, contexts, graph, rule

    project_id, teams = administrator(analyst)
    imported(analyst, project_id, "7.1.1", body(graph({"root": ["X"], "X": []})))
    apply_policy(analyst, project_id, [rule("root", teams["Platform"])])
    old = contexts(analyst, project_id)
    item = next(item for item in old["items"] if item["component_ref"] == "X")
    apply_policy(analyst, project_id, [rule("root", teams["Operations"])], request_id="reassign")
    base = f"/api/v3/projects/{project_id}/states/{old['state']}/contexts"
    historical = analyst.get(f"{base}/{item['id']}")
    assert historical.status_code == 200
    assert historical.json()["item"] == item
    assert historical.json()["policy_state"] == old["policy_state"]
    assert analyst.get(f"{base}/{'0' * 64}").status_code == 404
    login(analyst, "operations")
    assert analyst.get(f"{base}/{item['id']}").status_code == 404
