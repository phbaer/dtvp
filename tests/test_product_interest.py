"""Product interest from the browser (ADR 0004 step 4a): one lease per
(user, client_id), renewed by the leader, ended by an empty list or the
watch TTL."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dtvp.event_hub import EventHub
from dtvp.event_routes import EventRouteDeps, create_event_router
from dtvp.product_interest import MAX_LEASES_PER_USER, ProductInterest, watch_ttl_seconds
from tests.test_event_routes import FakeAuth


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_a_lease_lives_for_the_ttl_after_its_last_renewal():
    clock = Clock()
    interest = ProductInterest(ttl_seconds=900, clock=clock)

    interest.put("rita", "b1", ["App", "Lib", "App", " "])
    assert interest.watched() == {"App", "Lib"}
    clock.now += 600
    interest.put("rita", "b1", ["App"])  # renewed, with the new union
    clock.now += 600
    assert interest.watched() == {"App"}
    clock.now += 301
    assert interest.watched() == set()


def test_leases_are_per_user_and_browser_and_an_empty_list_ends_one():
    interest = ProductInterest(ttl_seconds=900, clock=Clock())
    interest.put("rita", "b1", ["App"])
    interest.put("rita", "b2", ["Lib"])
    interest.put("anna", "b1", ["Tool"])

    assert interest.watched() == {"App", "Lib", "Tool"}
    assert interest.put("rita", "b1", []) is None
    assert interest.watched() == {"Lib", "Tool"}
    assert {(lease.user, lease.client_id) for lease in interest.leases()} == {
        ("rita", "b2"), ("anna", "b1"),
    }


def test_a_user_holds_a_bounded_number_of_leases():
    clock = Clock()
    interest = ProductInterest(ttl_seconds=900, clock=clock)
    for index in range(MAX_LEASES_PER_USER + 3):
        clock.now += 1
        interest.put("rita", f"b{index}", [f"P{index}"])

    assert len(interest.leases()) == MAX_LEASES_PER_USER
    assert "P0" not in interest.watched() and f"P{MAX_LEASES_PER_USER + 2}" in interest.watched()


def test_the_ttl_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("DTVP_SYNC_WATCH_TTL_SECONDS", "120")
    assert watch_ttl_seconds() == 120
    monkeypatch.setenv("DTVP_SYNC_WATCH_TTL_SECONDS", "nonsense")
    assert watch_ttl_seconds() == 900


def _client(interest):
    deps = EventRouteDeps(
        hub=EventHub(boot_id="boot1"),
        authenticate=FakeAuth(),
        get_user_role=lambda user: "ANALYST",
        build="1",
        source_state=lambda: {},
        interest=interest,
    )
    app = FastAPI()
    app.include_router(create_event_router(deps), prefix="/api")
    return TestClient(app)


def test_the_route_renews_and_ends_the_lease_of_the_signed_in_user():
    clock = Clock()
    interest = ProductInterest(ttl_seconds=900, clock=clock)
    client = _client(interest)
    put = lambda body, user="rita": client.put(  # noqa: E731
        "/api/events/interest", json=body, headers={"X-User": user} if user else {}
    )

    first = put({"client_id": "b1", "products": ["Lib", "App"]})
    assert first.status_code == 200
    assert first.json() == {"products": ["App", "Lib"], "ttl_seconds": 900}
    assert [(lease.user, lease.products) for lease in interest.leases()] == [("rita", ("App", "Lib"))]

    clock.now += 800
    put({"client_id": "b1", "products": ["App", "Lib"]})  # renewal
    clock.now += 800
    assert interest.watched() == {"App", "Lib"}
    clock.now += 101
    assert interest.watched() == set()

    put({"client_id": "b1", "products": ["App"]})
    assert put({"client_id": "b1", "products": []}).json() == {"products": [], "ttl_seconds": 0}
    assert interest.watched() == set()


def test_the_route_checks_its_input_and_the_user():
    client = _client(ProductInterest(ttl_seconds=900, clock=Clock()))
    put = lambda body, user="rita": client.put(  # noqa: E731
        "/api/events/interest", json=body, headers={"X-User": user} if user else {}
    )

    assert put({"client_id": "b1", "products": ["App"]}, user=None).status_code == 401
    assert put({"client_id": "", "products": ["App"]}).status_code == 422
    assert put({"client_id": "b1", "products": ["x" * 501]}).status_code == 422
    assert put({"client_id": "b1", "products": ["p"] * 201}).status_code == 422
    assert _client(None).put(
        "/api/events/interest", json={"client_id": "b1", "products": []}, headers={"X-User": "rita"}
    ).status_code == 404
